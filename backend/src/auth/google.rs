//! Google sign-in: OpenID Connect Authorization Code flow with PKCE
//! (CASA 3.2.1). This is the only module that makes outbound HTTP requests,
//! and only to Google's fixed token endpoint (lint:outbound-http, CASA 5.1.5).

use std::sync::Arc;
use std::time::Duration;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::Url;
use serde_json::Value;

use super::LoginRejected;
use super::token::ct_eq;
use crate::config::{OAuthConfig, Secret};

const AUTHORIZE_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
/// Google's issuer. ID tokens may carry either form (Google OIDC docs).
pub const ISSUER: &str = "https://accounts.google.com";
const ISSUER_SHORT: &str = "accounts.google.com";
/// Sign-in only needs identity. Restricted scopes are requested separately.
const SCOPES: &str = "openid email";
/// Largest token-endpoint response we will read.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
/// Tolerated clock difference with Google when checking `exp`/`iat`.
const CLOCK_SKEW_SECS: i64 = 60;

/// The Google user an ID token vouches for.
#[derive(Debug, Clone)]
pub struct Identity {
    /// Google's stable account ID; the key we match users on.
    pub sub: String,
    pub email: String,
}

/// A URL on Google's authorization endpoint. The field is private, so the only
/// way to obtain one is `GoogleClient::authorize_url`; the redirect helper
/// relies on that (CASA 5.1.2).
pub struct AuthorizeUrl(String);

impl AuthorizeUrl {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub struct GoogleClient {
    http: reqwest::Client,
    client_id: String,
    client_secret: Secret,
    redirect_uri: Url,
    authorize_endpoint: Url,
    token_endpoint: Url,
}

impl GoogleClient {
    pub fn new(cfg: &OAuthConfig) -> anyhow::Result<Self> {
        Self::build(
            cfg,
            Url::parse(AUTHORIZE_ENDPOINT)?,
            Url::parse(TOKEN_ENDPOINT)?,
            true,
        )
    }

    /// Points the client at a local fake token endpoint (plain http).
    #[cfg(test)]
    pub fn for_test(cfg: &OAuthConfig, token_endpoint: Url) -> anyhow::Result<Self> {
        Self::build(cfg, Url::parse(AUTHORIZE_ENDPOINT)?, token_endpoint, false)
    }

    fn build(
        cfg: &OAuthConfig,
        authorize_endpoint: Url,
        token_endpoint: Url,
        https_only: bool,
    ) -> anyhow::Result<Self> {
        // rustls with the Mozilla root set: certificate and hostname checks are
        // always on, TLS 1.2+ only (CASA 4.1.1, 4.1.2).
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();

        let http = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .https_only(https_only)
            // A redirect from the token endpoint is never legitimate; following
            // one would resend the code and client credentials elsewhere.
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .build()?;

        Ok(Self {
            http,
            client_id: cfg.client_id.clone(),
            client_secret: cfg.client_secret.clone(),
            redirect_uri: cfg.redirect_uri.clone(),
            authorize_endpoint,
            token_endpoint,
        })
    }

    /// Where to send the browser to start sign-in.
    pub fn authorize_url(&self, state: &str, code_challenge: &str, nonce: &str) -> AuthorizeUrl {
        let mut url = self.authorize_endpoint.clone();
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", self.redirect_uri.as_str())
            .append_pair("scope", SCOPES)
            .append_pair("state", state)
            .append_pair("nonce", nonce)
            .append_pair("code_challenge", code_challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("prompt", "select_account");
        AuthorizeUrl(url.into())
    }

    /// Redeems the authorization code (with the PKCE verifier) for an ID token
    /// and returns the identity it proves. Google's access and refresh tokens
    /// are discarded: sign-in doesn't need them, so they are never stored.
    pub async fn exchange_code(
        &self,
        code: &str,
        code_verifier: &str,
        expected_nonce: &str,
    ) -> Result<Identity, LoginRejected> {
        let form = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.redirect_uri.as_str()),
            ("client_id", &self.client_id),
            ("client_secret", self.client_secret.expose()),
            ("code_verifier", code_verifier),
        ];
        let resp = self
            .http
            .post(self.token_endpoint.clone())
            .form(&form)
            .send()
            .await
            .map_err(|e| LoginRejected::ProviderUnreachable(e.without_url().to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(LoginRejected::ProviderStatus(status.as_u16()));
        }
        if resp
            .content_length()
            .is_some_and(|n| n > MAX_RESPONSE_BYTES as u64)
        {
            return Err(LoginRejected::MalformedProviderResponse);
        }
        let body = resp
            .bytes()
            .await
            .map_err(|e| LoginRejected::ProviderUnreachable(e.without_url().to_string()))?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(LoginRejected::MalformedProviderResponse);
        }
        // Parsed as a Value, not a struct: Google's response carries fields we
        // ignore, and only the ID token is read.
        let json: Value =
            serde_json::from_slice(&body).map_err(|_| LoginRejected::MalformedProviderResponse)?;
        let id_token = json
            .get("id_token")
            .and_then(Value::as_str)
            .ok_or(LoginRejected::MalformedProviderResponse)?;

        validate_id_token(
            id_token,
            &self.client_id,
            expected_nonce,
            time::OffsetDateTime::now_utc().unix_timestamp(),
        )
    }
}

/// Checks an ID token received straight from Google's token endpoint.
///
/// The token came over a TLS connection we opened to Google and verified, so
/// OpenID Connect Core 1.0 §3.1.3.7 step 6 lets us rely on TLS instead of the
/// JWS signature. Every claim is still checked: issuer, audience, expiry,
/// issue time, nonce (replay) and a verified email.
pub fn validate_id_token(
    id_token: &str,
    client_id: &str,
    expected_nonce: &str,
    now: i64,
) -> Result<Identity, LoginRejected> {
    let mut parts = id_token.split('.');
    let (Some(_header), Some(payload), Some(_sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(LoginRejected::MalformedProviderResponse);
    };
    let claims: Value = URL_SAFE_NO_PAD
        .decode(payload)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or(LoginRejected::MalformedProviderResponse)?;

    let str_claim = |name: &'static str| {
        claims
            .get(name)
            .and_then(Value::as_str)
            .ok_or(LoginRejected::InvalidClaim(name))
    };
    let int_claim = |name: &'static str| {
        claims
            .get(name)
            .and_then(Value::as_i64)
            .ok_or(LoginRejected::InvalidClaim(name))
    };

    let iss = str_claim("iss")?;
    if iss != ISSUER && iss != ISSUER_SHORT {
        return Err(LoginRejected::InvalidClaim("iss"));
    }

    let aud_ok = match claims.get("aud") {
        Some(Value::String(aud)) => aud == client_id,
        // Several audiences: ours must be one, and `azp` must name us.
        Some(Value::Array(auds)) => {
            auds.iter().any(|a| a.as_str() == Some(client_id))
                && claims.get("azp").and_then(Value::as_str) == Some(client_id)
        }
        _ => false,
    };
    if !aud_ok {
        return Err(LoginRejected::InvalidClaim("aud"));
    }

    if int_claim("exp")? + CLOCK_SKEW_SECS <= now {
        return Err(LoginRejected::InvalidClaim("exp"));
    }
    if int_claim("iat")? - CLOCK_SKEW_SECS > now {
        return Err(LoginRejected::InvalidClaim("iat"));
    }

    if !ct_eq(str_claim("nonce")?, expected_nonce) {
        return Err(LoginRejected::InvalidClaim("nonce"));
    }

    let sub = str_claim("sub")?;
    if sub.is_empty() || sub.len() > 255 {
        return Err(LoginRejected::InvalidClaim("sub"));
    }
    let email = str_claim("email")?;
    if email.is_empty() || email.len() > 320 {
        return Err(LoginRejected::InvalidClaim("email"));
    }
    // Google sends a bool; very old tokens used the string "true".
    let email_verified = match claims.get("email_verified") {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s == "true",
        _ => false,
    };
    if !email_verified {
        return Err(LoginRejected::InvalidClaim("email_verified"));
    }

    Ok(Identity {
        sub: sub.to_owned(),
        email: email.to_owned(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod tests {
    use super::*;
    use crate::config::tests::test_config;
    use serde_json::json;

    pub(crate) const CLIENT_ID: &str = "test-client.apps.googleusercontent.com";
    const NOW: i64 = 1_800_000_000;

    /// An unsigned JWT with the given claims (signatures are not checked; see
    /// `validate_id_token`).
    pub(crate) fn fake_id_token(claims: &Value) -> String {
        let enc = |v: &Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap());
        format!("{}.{}.sig", enc(&json!({"alg": "RS256"})), enc(claims))
    }

    pub(crate) fn good_claims(nonce: &str, sub: &str, now: i64) -> Value {
        json!({
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "sub": sub,
            "email": format!("{sub}@example.com"),
            "email_verified": true,
            "nonce": nonce,
            "iat": now,
            "exp": now + 3600,
        })
    }

    fn check(claims: &Value) -> Result<Identity, LoginRejected> {
        validate_id_token(&fake_id_token(claims), CLIENT_ID, "n0nce", NOW)
    }

    #[test]
    fn accepts_valid_id_token() {
        let id = check(&good_claims("n0nce", "1234", NOW)).unwrap();
        assert_eq!(id.sub, "1234");
        assert_eq!(id.email, "1234@example.com");
    }

    #[test]
    fn rejects_each_bad_claim() {
        // CASA 3.2.1 / 3.2.2: wrong issuer, audience, expiry, replayed nonce,
        // unverified email: each must fail on its own.
        let cases: [(&str, Value); 9] = [
            ("iss", json!("https://evil.example.com")),
            ("aud", json!("someone-else.apps.googleusercontent.com")),
            ("aud", json!(["someone-else", CLIENT_ID])),
            ("exp", json!(NOW - 3600)),
            ("iat", json!(NOW + 3600)),
            ("nonce", json!("replayed-nonce")),
            ("email_verified", json!(false)),
            ("sub", json!("")),
            ("email", json!(null)),
        ];
        for (claim, value) in cases {
            let mut c = good_claims("n0nce", "1234", NOW);
            c[claim] = value.clone();
            assert!(check(&c).is_err(), "accepted {claim}={value}");
        }
        for claim in ["iss", "aud", "exp", "nonce", "sub", "email_verified"] {
            let mut c = good_claims("n0nce", "1234", NOW);
            c.as_object_mut().unwrap().remove(claim);
            assert!(check(&c).is_err(), "accepted missing {claim}");
        }
    }

    #[test]
    fn rejects_malformed_id_tokens() {
        for bad in ["", "a.b", "a.b.c.d", "a.!!!.c", "a.e30.c"] {
            assert!(
                validate_id_token(bad, CLIENT_ID, "n0nce", NOW).is_err(),
                "accepted {bad}"
            );
        }
    }

    #[test]
    fn authorize_url_uses_code_flow_with_pkce_and_fixed_redirect() {
        // CASA 3.2.1 (code + S256 PKCE) and 3.2.2 (state, fixed redirect_uri).
        let client = GoogleClient::new(&test_config().oauth).unwrap();
        let url = Url::parse(client.authorize_url("st", "ch", "nn").as_str()).unwrap();
        assert_eq!(
            url.origin().ascii_serialization(),
            "https://accounts.google.com"
        );
        let q: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(q["response_type"], "code");
        assert_eq!(q["code_challenge_method"], "S256");
        assert_eq!(q["code_challenge"], "ch");
        assert_eq!(q["state"], "st");
        assert_eq!(q["nonce"], "nn");
        assert_eq!(q["redirect_uri"], "http://localhost:8000/api/auth/callback");
        assert_eq!(q["scope"], "openid email");
        assert!(!q.contains_key("client_secret"));
    }

    #[actix_web::test]
    async fn production_client_refuses_plain_http() {
        // CASA 4.1.1: the real client is https-only, even if pointed elsewhere.
        let cfg = test_config().oauth;
        let mut client = GoogleClient::new(&cfg).unwrap();
        client.token_endpoint = Url::parse("http://127.0.0.1:9/token").unwrap();
        let err = client.exchange_code("c", "v", "n").await.unwrap_err();
        assert!(
            matches!(err, LoginRejected::ProviderUnreachable(_)),
            "{err:?}"
        );
    }
}
