//! Google sign-in, Gmail linking and the Gmail API: OAuth 2.0 Authorization
//! Code flow with PKCE (CASA 3.2.1). This is the only module that makes
//! outbound HTTP requests, and only to Google's fixed endpoints below
//! (lint:outbound-http, CASA 5.1.5). Nothing from a request picks a host.

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
const REVOKE_ENDPOINT: &str = "https://oauth2.googleapis.com/revoke";
/// Gmail API for the mailbox the access token belongs to. Ends in `/` so
/// `Url::join` stays under it.
const GMAIL_API: &str = "https://gmail.googleapis.com/gmail/v1/users/me/";
/// Google's issuer. ID tokens may carry either form (Google OIDC docs).
pub const ISSUER: &str = "https://accounts.google.com";
const ISSUER_SHORT: &str = "accounts.google.com";
/// Read-only Gmail access (restricted scope). Requested only when a signed-in
/// user links a mailbox, never at sign-in.
pub const GMAIL_READONLY: &str = "https://www.googleapis.com/auth/gmail.readonly";
/// Sign-in only needs identity and the user's name (`profile` gives
/// `given_name` / `family_name`).
const SIGN_IN_SCOPES: &str = "openid email profile";
/// Linking needs the mailbox's identity (to tell linked accounts apart) and
/// read-only mail.
const LINK_SCOPES: &str = "openid email https://www.googleapis.com/auth/gmail.readonly";
/// Same bound as names entered at registration (users.first_name/last_name).
const MAX_NAME_CHARS: usize = 100;
/// Largest token or list response we will read.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
/// Largest single message we will read. `format=full` carries bodies but not
/// attachment data, so real mail stays far below this.
const MAX_MESSAGE_BYTES: usize = 8 * 1024 * 1024;
/// Gmail's `maxResults` ceiling for one list page.
const MAX_LIST_RESULTS: u32 = 500;
/// Tolerated clock difference with Google when checking `exp`/`iat`.
const CLOCK_SKEW_SECS: i64 = 60;

/// Why a Google authorization was started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    SignIn,
    /// A signed-in user is linking a Gmail mailbox (offline, read-only).
    LinkGmail,
}

/// The Google user an ID token vouches for.
#[derive(Debug, Clone)]
pub struct Identity {
    /// Google's stable account ID; the key we match users on.
    pub sub: String,
    pub email: String,
    /// `given_name` / `family_name`. Optional: Google omits them for some
    /// accounts, and a user may have only one.
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

/// What a redeemed authorization code gave us.
pub struct Grant {
    pub identity: Identity,
    /// Present only for offline (linking) authorizations. Sign-in drops it.
    pub refresh_token: Option<Secret>,
    /// Scopes the user actually granted; they can untick some.
    scopes: Vec<String>,
}

impl Grant {
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }
}

/// A failed Gmail API or token-refresh call. Never carries a token.
#[derive(Debug)]
pub enum GoogleApiError {
    Unreachable(String),
    Status(u16),
    /// The user revoked our access, or the grant expired: relink needed.
    Revoked,
    Malformed,
}

impl std::fmt::Display for GoogleApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GoogleApiError::Unreachable(e) => write!(f, "Google unreachable: {e}"),
            GoogleApiError::Status(s) => write!(f, "Google returned HTTP {s}"),
            GoogleApiError::Revoked => f.write_str("Google access was revoked or expired"),
            GoogleApiError::Malformed => f.write_str("malformed Google response"),
        }
    }
}

/// Reading a response body failed.
enum BodyError {
    Unreachable(String),
    TooLarge,
    Malformed,
}

impl From<BodyError> for LoginRejected {
    fn from(e: BodyError) -> Self {
        match e {
            BodyError::Unreachable(e) => LoginRejected::ProviderUnreachable(e),
            BodyError::TooLarge | BodyError::Malformed => LoginRejected::MalformedProviderResponse,
        }
    }
}

impl From<BodyError> for GoogleApiError {
    fn from(e: BodyError) -> Self {
        match e {
            BodyError::Unreachable(e) => GoogleApiError::Unreachable(e),
            BodyError::TooLarge | BodyError::Malformed => GoogleApiError::Malformed,
        }
    }
}

fn unreachable(e: reqwest::Error) -> GoogleApiError {
    GoogleApiError::Unreachable(e.without_url().to_string())
}

/// Reads at most `max` bytes of JSON. Parsed as a `Value`, not a struct:
/// Google's responses carry fields we ignore.
async fn read_json(resp: reqwest::Response, max: usize) -> Result<Value, BodyError> {
    if resp.content_length().is_some_and(|n| n > max as u64) {
        return Err(BodyError::TooLarge);
    }
    let body = resp
        .bytes()
        .await
        .map_err(|e| BodyError::Unreachable(e.without_url().to_string()))?;
    if body.len() > max {
        return Err(BodyError::TooLarge);
    }
    serde_json::from_slice(&body).map_err(|_| BodyError::Malformed)
}

/// Gmail message IDs are short hex strings. Anything else is refused before
/// it goes into a URL path.
pub fn valid_gmail_id(id: &str) -> bool {
    (1..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Cleans an optional name claim. A missing, non-string or blank value is
/// `None`; control characters are dropped and long names are cut to fit the
/// database limit. A bad name never blocks sign-in.
fn name_claim(claims: &Value, name: &str) -> Option<String> {
    let raw = claims.get(name)?.as_str()?;
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .chars()
        .take(MAX_NAME_CHARS)
        .collect();
    let cleaned = cleaned.trim_end().to_owned();
    (!cleaned.is_empty()).then_some(cleaned)
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
    revoke_endpoint: Url,
    gmail_api: Url,
}

impl GoogleClient {
    pub fn new(cfg: &OAuthConfig) -> anyhow::Result<Self> {
        Self::build(
            cfg,
            Url::parse(AUTHORIZE_ENDPOINT)?,
            Url::parse(TOKEN_ENDPOINT)?,
            Url::parse(REVOKE_ENDPOINT)?,
            Url::parse(GMAIL_API)?,
            true,
        )
    }

    /// Points the client at a local fake Google (plain http) serving
    /// `/token`, `/revoke` and `/gmail/v1/users/me/`.
    #[cfg(test)]
    pub fn for_test(cfg: &OAuthConfig, base: Url) -> anyhow::Result<Self> {
        Self::build(
            cfg,
            Url::parse(AUTHORIZE_ENDPOINT)?,
            base.join("token")?,
            base.join("revoke")?,
            base.join("gmail/v1/users/me/")?,
            false,
        )
    }

    fn build(
        cfg: &OAuthConfig,
        authorize_endpoint: Url,
        token_endpoint: Url,
        revoke_endpoint: Url,
        gmail_api: Url,
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
            // A redirect from Google's API is never legitimate; following one
            // would resend the code, credentials or bearer token elsewhere.
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
            revoke_endpoint,
            gmail_api,
        })
    }

    /// Where to send the browser to start an authorization.
    pub fn authorize_url(
        &self,
        purpose: Purpose,
        state: &str,
        code_challenge: &str,
        nonce: &str,
    ) -> AuthorizeUrl {
        let mut url = self.authorize_endpoint.clone();
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("response_type", "code")
                .append_pair("client_id", &self.client_id)
                .append_pair("redirect_uri", self.redirect_uri.as_str())
                .append_pair("state", state)
                .append_pair("nonce", nonce)
                .append_pair("code_challenge", code_challenge)
                .append_pair("code_challenge_method", "S256");
            match purpose {
                Purpose::SignIn => {
                    q.append_pair("scope", SIGN_IN_SCOPES)
                        .append_pair("prompt", "select_account");
                }
                Purpose::LinkGmail => {
                    // `offline` + `consent` makes Google issue a refresh
                    // token every time, even for a mailbox linked before.
                    q.append_pair("scope", LINK_SCOPES)
                        .append_pair("access_type", "offline")
                        .append_pair("prompt", "consent select_account");
                }
            }
        }
        AuthorizeUrl(url.into())
    }

    /// Redeems the authorization code (with the PKCE verifier) and checks the
    /// ID token. The access token is discarded; the refresh token is returned
    /// only if Google issued one (offline linking).
    pub async fn exchange_code(
        &self,
        code: &str,
        code_verifier: &str,
        expected_nonce: &str,
    ) -> Result<Grant, LoginRejected> {
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
        let json = read_json(resp, MAX_RESPONSE_BYTES).await?;
        let id_token = json
            .get("id_token")
            .and_then(Value::as_str)
            .ok_or(LoginRejected::MalformedProviderResponse)?;

        let identity = validate_id_token(
            id_token,
            &self.client_id,
            expected_nonce,
            time::OffsetDateTime::now_utc().unix_timestamp(),
        )?;
        let refresh_token = json
            .get("refresh_token")
            .and_then(Value::as_str)
            .filter(|t| !t.is_empty() && t.len() <= 2048)
            .map(Secret::new);
        let scopes = json
            .get("scope")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .split_ascii_whitespace()
            .map(str::to_owned)
            .collect();
        Ok(Grant {
            identity,
            refresh_token,
            scopes,
        })
    }

    /// Trades a stored refresh token for a short-lived access token. The
    /// access token is only ever held in memory for one import.
    pub async fn refresh_access_token(&self, refresh: &Secret) -> Result<Secret, GoogleApiError> {
        let form = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh.expose()),
            ("client_id", &self.client_id),
            ("client_secret", self.client_secret.expose()),
        ];
        let resp = self
            .http
            .post(self.token_endpoint.clone())
            .form(&form)
            .send()
            .await
            .map_err(unreachable)?;
        let status = resp.status();
        // RFC 6749 §5.2: a dead grant is 400 `invalid_grant`.
        if status.as_u16() == 400 || status.as_u16() == 401 {
            return Err(GoogleApiError::Revoked);
        }
        if !status.is_success() {
            return Err(GoogleApiError::Status(status.as_u16()));
        }
        let json = read_json(resp, MAX_RESPONSE_BYTES).await?;
        json.get("access_token")
            .and_then(Value::as_str)
            .filter(|t| !t.is_empty())
            .map(Secret::new)
            .ok_or(GoogleApiError::Malformed)
    }

    async fn gmail_get(
        &self,
        url: Url,
        access: &Secret,
        max: usize,
    ) -> Result<Value, GoogleApiError> {
        let resp = self
            .http
            .get(url)
            .bearer_auth(access.expose())
            .send()
            .await
            .map_err(unreachable)?;
        let status = resp.status();
        if status.as_u16() == 401 {
            return Err(GoogleApiError::Revoked);
        }
        if !status.is_success() {
            return Err(GoogleApiError::Status(status.as_u16()));
        }
        Ok(read_json(resp, max).await?)
    }

    /// IDs of the newest `max` messages in the mailbox (Gmail excludes spam
    /// and trash by default).
    pub async fn list_message_ids(
        &self,
        access: &Secret,
        max: u32,
    ) -> Result<Vec<String>, GoogleApiError> {
        let mut url = self
            .gmail_api
            .join("messages")
            .map_err(|_| GoogleApiError::Malformed)?;
        url.query_pairs_mut()
            .append_pair("maxResults", &max.clamp(1, MAX_LIST_RESULTS).to_string());
        let json = self.gmail_get(url, access, MAX_RESPONSE_BYTES).await?;
        let Some(list) = json.get("messages") else {
            // An empty mailbox has no `messages` key at all.
            return Ok(Vec::new());
        };
        let list = list.as_array().ok_or(GoogleApiError::Malformed)?;
        Ok(list
            .iter()
            .filter_map(|m| m.get("id").and_then(Value::as_str))
            .filter(|id| valid_gmail_id(id))
            .take(max as usize)
            .map(str::to_owned)
            .collect())
    }

    /// One message with headers and body parts (`format=full`).
    pub async fn get_message(&self, access: &Secret, id: &str) -> Result<Value, GoogleApiError> {
        if !valid_gmail_id(id) {
            return Err(GoogleApiError::Malformed);
        }
        let mut url = self
            .gmail_api
            .join("messages/")
            .map_err(|_| GoogleApiError::Malformed)?;
        url.path_segments_mut()
            .map_err(|_| GoogleApiError::Malformed)?
            .pop_if_empty()
            .push(id);
        url.query_pairs_mut().append_pair("format", "full");
        self.gmail_get(url, access, MAX_MESSAGE_BYTES).await
    }

    /// Tells Google to revoke a refresh token (when a mailbox is unlinked).
    pub async fn revoke(&self, refresh: &Secret) -> Result<(), GoogleApiError> {
        let resp = self
            .http
            .post(self.revoke_endpoint.clone())
            .form(&[("token", refresh.expose())])
            .send()
            .await
            .map_err(unreachable)?;
        let status = resp.status();
        // 400 means Google already considers it invalid: nothing to revoke.
        if status.is_success() || status.as_u16() == 400 {
            Ok(())
        } else {
            Err(GoogleApiError::Status(status.as_u16()))
        }
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
        first_name: name_claim(&claims, "given_name"),
        last_name: name_claim(&claims, "family_name"),
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
            "given_name": "Ada",
            "family_name": "Lovelace",
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
        assert_eq!(id.first_name.as_deref(), Some("Ada"));
        assert_eq!(id.last_name.as_deref(), Some("Lovelace"));
    }

    #[test]
    fn name_claims_are_optional_and_cleaned() {
        let with = |given: Value, family: Value| {
            let mut c = good_claims("n0nce", "1234", NOW);
            c["given_name"] = given;
            c["family_name"] = family;
            check(&c).unwrap()
        };
        // Missing, blank or non-string names never block sign-in.
        let id = with(json!(null), json!("   "));
        assert_eq!((id.first_name, id.last_name), (None, None));
        let id = with(json!(42), json!(["x"]));
        assert_eq!((id.first_name, id.last_name), (None, None));
        let mut c = good_claims("n0nce", "1234", NOW);
        c.as_object_mut().unwrap().remove("given_name");
        assert_eq!(check(&c).unwrap().first_name, None);
        // Trimmed, control characters dropped, cut to the column limit.
        let id = with(json!("  Ada\u{7}\n "), json!("é".repeat(150)));
        assert_eq!(id.first_name.as_deref(), Some("Ada"));
        assert_eq!(id.last_name.unwrap().chars().count(), MAX_NAME_CHARS);
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
        for purpose in [Purpose::SignIn, Purpose::LinkGmail] {
            let url = Url::parse(client.authorize_url(purpose, "st", "ch", "nn").as_str()).unwrap();
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
            assert!(!q.contains_key("client_secret"));
        }
    }

    #[test]
    fn gmail_scope_is_requested_only_when_linking() {
        // Least privilege: sign-in never asks for mail; linking asks for
        // read-only mail and nothing broader.
        let client = GoogleClient::new(&test_config().oauth).unwrap();
        let query = |purpose| -> std::collections::HashMap<String, String> {
            Url::parse(client.authorize_url(purpose, "st", "ch", "nn").as_str())
                .unwrap()
                .query_pairs()
                .into_owned()
                .collect()
        };
        let sign_in = query(Purpose::SignIn);
        assert_eq!(sign_in["scope"], "openid email profile");
        assert!(!sign_in.contains_key("access_type"));
        let link = query(Purpose::LinkGmail);
        assert_eq!(
            link["scope"],
            "openid email https://www.googleapis.com/auth/gmail.readonly"
        );
        assert_eq!(link["access_type"], "offline");
        assert_eq!(link["prompt"], "consent select_account");
    }

    #[test]
    fn gmail_ids_are_checked_before_use_in_a_url() {
        // CASA 5.1.5: nothing but a plain ID reaches the Gmail URL path.
        assert!(valid_gmail_id("18c2f0a9b3d4e5f6"));
        for bad in ["", "../../labels", "a/b", "a?b", "a%2Fb", &"a".repeat(65)] {
            assert!(!valid_gmail_id(bad), "accepted {bad:?}");
        }
    }

    #[actix_web::test]
    async fn production_client_refuses_plain_http() {
        // CASA 4.1.1: the real client is https-only, even if pointed elsewhere.
        let cfg = test_config().oauth;
        let mut client = GoogleClient::new(&cfg).unwrap();
        client.token_endpoint = Url::parse("http://127.0.0.1:9/token").unwrap();
        let err = client.exchange_code("c", "v", "n").await.err().unwrap();
        assert!(
            matches!(err, LoginRejected::ProviderUnreachable(_)),
            "{err:?}"
        );
    }
}
