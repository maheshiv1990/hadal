//! Google sign-in, Gmail linking and the Gmail API: OAuth 2.0 Authorization
//! Code flow with PKCE (CASA 3.2.1). This is the only module that makes
//! outbound HTTP requests, and only to Google's fixed endpoints below
//! (lint:outbound-http, CASA 5.1.5). Nothing from a request picks a host.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::Url;
use serde_json::Value;

use super::LoginRejected;
use super::token::ct_eq;
use crate::config::{OAuthConfig, Secret};

const AUTHORIZE_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
const REVOKE_ENDPOINT: &str = "https://oauth2.googleapis.com/revoke";
/// Google's public signing keys (JWKS), for the tokens Pub/Sub signs its
/// push requests with.
const CERTS_ENDPOINT: &str = "https://www.googleapis.com/oauth2/v3/certs";
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
/// Largest attachment response we will read: Gmail's 25 MB attachment limit
/// as base64url inside JSON, plus room for the envelope.
const MAX_ATTACHMENT_RESPONSE_BYTES: usize = 36 * 1024 * 1024;
/// A large attachment can take longer than the client's default timeout, but
/// must still finish before nginx gives up (`proxy_read_timeout 30s`).
const ATTACHMENT_TIMEOUT: Duration = Duration::from_secs(25);
/// Gmail's `maxResults` ceiling for one list page.
const MAX_LIST_RESULTS: u32 = 500;
/// Tolerated clock difference with Google when checking `exp`/`iat`.
const CLOCK_SKEW_SECS: i64 = 60;
/// Largest history page we will read: up to 500 change records.
const MAX_HISTORY_BYTES: usize = 2 * 1024 * 1024;
/// Gmail history IDs are unsigned 64-bit numbers, sent as strings.
const MAX_HISTORY_ID_DIGITS: usize = 20;
/// How long Google's signing keys are kept before they are fetched again.
const KEYS_TTL: Duration = Duration::from_secs(60 * 60);
/// A token signed with a key we don't have makes us fetch the keys again
/// (Google rotates them), but at most this often: forged key IDs can't make
/// us call Google on every request.
const KEYS_REFETCH_GAP: Duration = Duration::from_secs(60);

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
    /// A failure status, with Google's machine-readable reason when it gave
    /// one (such as `rateLimitExceeded`): a short code, never a token.
    Status(u16, Option<String>),
    /// The user revoked our access, or the grant expired: relink needed.
    Revoked,
    Malformed,
}

impl GoogleApiError {
    /// Gmail asked us to slow down: 429, or 403 with a rate-limit reason.
    pub fn is_rate_limited(&self) -> bool {
        match self {
            GoogleApiError::Status(429, _) => true,
            GoogleApiError::Status(403, Some(reason)) => reason.contains("ateLimitExceeded"),
            _ => false,
        }
    }
}

/// Google's error reason from an error response body (`error.errors[0].reason`,
/// else `error.status`), reduced to a short alphanumeric code. Reads at most
/// 4 KiB. Anything unexpected gives `None`.
async fn error_reason(resp: reqwest::Response) -> Option<String> {
    let json = read_json(resp, 4 * 1024).await.ok()?;
    let err = json.get("error")?;
    let reason = err
        .get("errors")
        .and_then(Value::as_array)
        .and_then(|e| e.first())
        .and_then(|e| e.get("reason"))
        .or_else(|| err.get("status"))?
        .as_str()?;
    let reason: String = reason
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .take(64)
        .collect();
    (!reason.is_empty()).then_some(reason)
}

/// Waits before each retry of a rate-limited Gmail call.
#[cfg(not(test))]
const RATE_LIMIT_BACKOFF: [Duration; 2] =
    [Duration::from_millis(1000), Duration::from_millis(2500)];
#[cfg(test)]
const RATE_LIMIT_BACKOFF: [Duration; 2] = [Duration::from_millis(5), Duration::from_millis(10)];

impl std::fmt::Display for GoogleApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GoogleApiError::Unreachable(e) => write!(f, "Google unreachable: {e}"),
            GoogleApiError::Status(s, Some(reason)) => {
                write!(f, "Google returned HTTP {s} ({reason})")
            }
            GoogleApiError::Status(s, None) => write!(f, "Google returned HTTP {s}"),
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

/// Gmail list page tokens are opaque, but only ever digits and letters.
/// Anything else is refused before it goes into a URL or the database (the
/// column allows at most 256 characters).
pub fn valid_page_token(token: &str) -> bool {
    (1..=256).contains(&token.len())
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Gmail attachment IDs are long base64url strings. Anything else is refused
/// before it goes into a URL path.
pub fn valid_attachment_id(id: &str) -> bool {
    (1..=2048).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A Gmail label ID as it may appear in a list filter: system labels are
/// upper-case words, user labels look like `Label_12`. Nothing else.
pub fn valid_label_id(id: &str) -> bool {
    (1..=80).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Gmail's counts for one label.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LabelCounts {
    /// Messages carrying the label (`messagesTotal`).
    pub messages: i64,
    /// Conversations carrying it (`threadsTotal`).
    pub threads: i64,
    /// Unread conversations (`threadsUnread`): the number Gmail's own
    /// sidebar shows, since Gmail groups mail into conversations by default.
    pub unread_threads: i64,
}

/// A count (`messagesTotal`, `threadsUnread`, …) from a Gmail label or
/// profile: a non-negative integer. Gmail leaves it out when it is zero.
fn count(json: &Value, field: &str) -> Result<i64, GoogleApiError> {
    match json.get(field) {
        None => Ok(0),
        Some(n) => n
            .as_i64()
            .filter(|n| *n >= 0)
            .ok_or(GoogleApiError::Malformed),
    }
}

/// A label the user made in Gmail (not a system label).
pub fn valid_user_label_id(id: &str) -> bool {
    id.strip_prefix("Label_")
        .is_some_and(|rest| (1..=64).contains(&rest.len()) && valid_label_id(rest))
}

/// One of the user's own Gmail labels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserLabel {
    pub id: String,
    pub name: String,
    /// `#rrggbb`, lower-case, if Gmail gives the label a colour.
    pub color: Option<String>,
}

/// Most characters of a label name we keep (Gmail allows 225).
const MAX_LABEL_NAME_CHARS: usize = 225;

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

/// A Gmail history ID: digits only, as Gmail sends them.
pub fn valid_history_id(id: &str) -> bool {
    (1..=MAX_HISTORY_ID_DIGITS).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_digit())
}

/// One change in a mailbox, from `users.history.list`, in the order Gmail
/// recorded them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryChange {
    /// A message arrived, was sent, or was saved as a draft.
    Added(String),
    /// A message was deleted for good.
    Deleted(String),
    /// Labels (such as `STARRED`, `TRASH` or `UNREAD`) were put on a message.
    LabelsAdded(String, Vec<String>),
    /// Labels were taken off a message.
    LabelsRemoved(String, Vec<String>),
}

/// One page of a mailbox's history.
#[derive(Debug)]
pub struct HistoryPage {
    pub changes: Vec<HistoryChange>,
    /// The next page, or `None` on the last one.
    pub next: Option<String>,
    /// The mailbox's history ID now: where the next read starts.
    pub history_id: String,
}

/// A mailbox's watch, as `users.watch` set it.
#[derive(Debug)]
pub struct Watch {
    /// When Gmail stops notifying unless the watch is renewed.
    pub expires_at: time::OffsetDateTime,
}

/// Why a Pub/Sub push request's token was refused. Logged, never sent back.
#[derive(Debug)]
pub enum PushRejected {
    Malformed,
    /// Not signed RS256 (`none`, an HMAC, …).
    Algorithm,
    UnknownKey,
    Signature,
    InvalidClaim(&'static str),
    /// Google's signing keys couldn't be fetched.
    KeysUnavailable(String),
}

impl std::fmt::Display for PushRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PushRejected::Malformed => f.write_str("malformed token"),
            PushRejected::Algorithm => f.write_str("token not signed with RS256"),
            PushRejected::UnknownKey => f.write_str("token signed with an unknown key"),
            PushRejected::Signature => f.write_str("bad token signature"),
            PushRejected::InvalidClaim(c) => write!(f, "invalid token claim: {c}"),
            PushRejected::KeysUnavailable(e) => write!(f, "Google signing keys unavailable: {e}"),
        }
    }
}

/// What a push token must say: the subscription's audience and the service
/// account it signs as.
pub struct PushExpectation<'a> {
    pub audience: &'a str,
    pub service_account: &'a str,
}

/// A Google RSA signing key.
#[derive(Clone)]
pub struct SigningKey {
    n: Vec<u8>,
    e: Vec<u8>,
}

#[derive(Default)]
struct KeyCache {
    keys: HashMap<String, SigningKey>,
    fetched: Option<Instant>,
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
    certs_endpoint: Url,
    keys: Mutex<KeyCache>,
}

impl GoogleClient {
    pub fn new(cfg: &OAuthConfig) -> anyhow::Result<Self> {
        Self::build(
            cfg,
            Url::parse(AUTHORIZE_ENDPOINT)?,
            Url::parse(TOKEN_ENDPOINT)?,
            Url::parse(REVOKE_ENDPOINT)?,
            Url::parse(GMAIL_API)?,
            Url::parse(CERTS_ENDPOINT)?,
            true,
        )
    }

    /// Points the client at a local fake Google (plain http) serving
    /// `/token`, `/revoke`, `/certs` and `/gmail/v1/users/me/`.
    #[cfg(test)]
    pub fn for_test(cfg: &OAuthConfig, base: Url) -> anyhow::Result<Self> {
        Self::build(
            cfg,
            Url::parse(AUTHORIZE_ENDPOINT)?,
            base.join("token")?,
            base.join("revoke")?,
            base.join("gmail/v1/users/me/")?,
            base.join("certs")?,
            false,
        )
    }

    fn build(
        cfg: &OAuthConfig,
        authorize_endpoint: Url,
        token_endpoint: Url,
        revoke_endpoint: Url,
        gmail_api: Url,
        certs_endpoint: Url,
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
            certs_endpoint,
            keys: Mutex::new(KeyCache::default()),
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
            return Err(GoogleApiError::Status(
                status.as_u16(),
                error_reason(resp).await,
            ));
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
        self.gmail_get_within(url, access, max, None).await
    }

    /// `gmail_get` with a longer timeout than the client's default. When
    /// Gmail rate-limits the call, it is retried after a short wait, twice.
    async fn gmail_get_within(
        &self,
        url: Url,
        access: &Secret,
        max: usize,
        timeout: Option<Duration>,
    ) -> Result<Value, GoogleApiError> {
        let mut waits = RATE_LIMIT_BACKOFF.iter();
        loop {
            let mut req = self.http.get(url.clone()).bearer_auth(access.expose());
            if let Some(t) = timeout {
                req = req.timeout(t);
            }
            let resp = req.send().await.map_err(unreachable)?;
            let status = resp.status();
            if status.as_u16() == 401 {
                return Err(GoogleApiError::Revoked);
            }
            if status.is_success() {
                return Ok(read_json(resp, max).await?);
            }
            let err = GoogleApiError::Status(status.as_u16(), error_reason(resp).await);
            match waits.next() {
                Some(wait) if err.is_rate_limited() => tokio::time::sleep(*wait).await,
                _ => return Err(err),
            }
        }
    }

    /// IDs of the newest `max` messages in the mailbox (Gmail excludes spam
    /// and trash by default), or only those carrying `label`. The label is
    /// one of our constants or a user label ID Gmail gave us, never request
    /// input, and is checked again here. The flag says whether the list is
    /// complete (Gmail has no further page).
    pub async fn list_message_ids(
        &self,
        access: &Secret,
        max: u32,
        label: Option<&str>,
    ) -> Result<(Vec<String>, bool), GoogleApiError> {
        let mut url = self
            .gmail_api
            .join("messages")
            .map_err(|_| GoogleApiError::Malformed)?;
        url.query_pairs_mut()
            .append_pair("maxResults", &max.clamp(1, MAX_LIST_RESULTS).to_string());
        if let Some(label) = label {
            if !valid_label_id(label) {
                return Err(GoogleApiError::Malformed);
            }
            url.query_pairs_mut().append_pair("labelIds", label);
            if label == "SPAM" {
                url.query_pairs_mut()
                    .append_pair("includeSpamTrash", "true");
            }
        }
        let (ids, next) = self.read_message_list(url, access, max).await?;
        Ok((ids, next.is_none()))
    }

    /// One page of the whole mailbox (spam and trash excluded), newest first:
    /// up to `max` IDs and the token for the next, older page, or `None` on
    /// the last page. `page_token` is one Gmail gave us, checked again here.
    pub async fn list_message_page(
        &self,
        access: &Secret,
        max: u32,
        page_token: Option<&str>,
    ) -> Result<(Vec<String>, Option<String>), GoogleApiError> {
        let mut url = self
            .gmail_api
            .join("messages")
            .map_err(|_| GoogleApiError::Malformed)?;
        url.query_pairs_mut()
            .append_pair("maxResults", &max.clamp(1, MAX_LIST_RESULTS).to_string());
        if let Some(page) = page_token {
            if !valid_page_token(page) {
                return Err(GoogleApiError::Malformed);
            }
            url.query_pairs_mut().append_pair("pageToken", page);
        }
        self.read_message_list(url, access, max).await
    }

    async fn read_message_list(
        &self,
        url: Url,
        access: &Secret,
        max: u32,
    ) -> Result<(Vec<String>, Option<String>), GoogleApiError> {
        let json = self.gmail_get(url, access, MAX_RESPONSE_BYTES).await?;
        let next = match json.get("nextPageToken") {
            None => None,
            Some(t) => Some(
                t.as_str()
                    .filter(|t| valid_page_token(t))
                    .ok_or(GoogleApiError::Malformed)?
                    .to_owned(),
            ),
        };
        let Some(list) = json.get("messages") else {
            // An empty mailbox or label has no `messages` key at all.
            return Ok((Vec::new(), next));
        };
        let list = list.as_array().ok_or(GoogleApiError::Malformed)?;
        let ids = list
            .iter()
            .filter_map(|m| m.get("id").and_then(Value::as_str))
            .filter(|id| valid_gmail_id(id))
            .take(max as usize)
            .map(str::to_owned)
            .collect();
        Ok((ids, next))
    }

    /// The user's own labels (Gmail's system labels are left out), at most
    /// `max`, with cleaned names and validated colours.
    pub async fn list_user_labels(
        &self,
        access: &Secret,
        max: usize,
    ) -> Result<Vec<UserLabel>, GoogleApiError> {
        let url = self
            .gmail_api
            .join("labels")
            .map_err(|_| GoogleApiError::Malformed)?;
        let json = self.gmail_get(url, access, MAX_RESPONSE_BYTES).await?;
        let Some(list) = json.get("labels") else {
            return Ok(Vec::new());
        };
        let list = list.as_array().ok_or(GoogleApiError::Malformed)?;
        Ok(list
            .iter()
            .filter(|l| l.get("type").and_then(Value::as_str) == Some("user"))
            .filter_map(|l| {
                let id = l.get("id")?.as_str().filter(|id| valid_user_label_id(id))?;
                let name: String = l
                    .get("name")?
                    .as_str()?
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(MAX_LABEL_NAME_CHARS)
                    .collect();
                let name = name.trim().to_owned();
                if name.is_empty() {
                    return None;
                }
                let color = l
                    .get("color")
                    .and_then(|c| c.get("backgroundColor"))
                    .and_then(Value::as_str)
                    .map(str::to_ascii_lowercase)
                    .filter(|c| {
                        c.len() == 7
                            && c.starts_with('#')
                            && c[1..].bytes().all(|b| b.is_ascii_hexdigit())
                    });
                Some(UserLabel {
                    id: id.to_owned(),
                    name,
                    color,
                })
            })
            .take(max)
            .collect())
    }

    /// Gmail's own counts for `label` (`users.labels.get`). The label is one
    /// of our constants or a label ID Gmail gave us, checked again here.
    pub async fn label_counts(
        &self,
        access: &Secret,
        label: &str,
    ) -> Result<LabelCounts, GoogleApiError> {
        if !valid_label_id(label) {
            return Err(GoogleApiError::Malformed);
        }
        let mut url = self
            .gmail_api
            .join("labels/")
            .map_err(|_| GoogleApiError::Malformed)?;
        url.path_segments_mut()
            .map_err(|_| GoogleApiError::Malformed)?
            .pop_if_empty()
            .push(label);
        let json = self.gmail_get(url, access, MAX_RESPONSE_BYTES).await?;
        Ok(LabelCounts {
            messages: count(&json, "messagesTotal")?,
            threads: count(&json, "threadsTotal")?,
            unread_threads: count(&json, "threadsUnread")?,
        })
    }

    /// Gmail's count of every message in the mailbox, spam and trash
    /// included (`messagesTotal` of `users.getProfile`).
    pub async fn mailbox_total(&self, access: &Secret) -> Result<i64, GoogleApiError> {
        let url = self
            .gmail_api
            .join("profile")
            .map_err(|_| GoogleApiError::Malformed)?;
        let json = self.gmail_get(url, access, MAX_RESPONSE_BYTES).await?;
        count(&json, "messagesTotal")
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

    /// One attachment of a message, as Gmail's base64url `data` string. The
    /// caller decodes it. Both IDs come from our own stored records, and are
    /// checked again here before they go into the URL path.
    pub async fn get_attachment(
        &self,
        access: &Secret,
        message_id: &str,
        attachment_id: &str,
    ) -> Result<String, GoogleApiError> {
        if !valid_gmail_id(message_id) || !valid_attachment_id(attachment_id) {
            return Err(GoogleApiError::Malformed);
        }
        let mut url = self
            .gmail_api
            .join("messages/")
            .map_err(|_| GoogleApiError::Malformed)?;
        url.path_segments_mut()
            .map_err(|_| GoogleApiError::Malformed)?
            .pop_if_empty()
            .push(message_id)
            .push("attachments")
            .push(attachment_id);
        let json = self
            .gmail_get_within(
                url,
                access,
                MAX_ATTACHMENT_RESPONSE_BYTES,
                Some(ATTACHMENT_TIMEOUT),
            )
            .await?;
        json.get("data")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or(GoogleApiError::Malformed)
    }

    /// The mailbox's current history ID (`users.getProfile`): changes after
    /// it are what the next history read returns.
    pub async fn history_id(&self, access: &Secret) -> Result<String, GoogleApiError> {
        let url = self
            .gmail_api
            .join("profile")
            .map_err(|_| GoogleApiError::Malformed)?;
        let json = self.gmail_get(url, access, MAX_RESPONSE_BYTES).await?;
        history_id_field(&json)
    }

    /// Changes to the mailbox after `start` (`users.history.list`), a page at
    /// a time. `start` is a history ID we stored, `page_token` one Gmail gave
    /// us; both are checked again here. Gmail answers 404 when `start` is too
    /// old to read from: the caller imports instead.
    pub async fn list_history(
        &self,
        access: &Secret,
        start: &str,
        page_token: Option<&str>,
    ) -> Result<HistoryPage, GoogleApiError> {
        if !valid_history_id(start) {
            return Err(GoogleApiError::Malformed);
        }
        let mut url = self
            .gmail_api
            .join("history")
            .map_err(|_| GoogleApiError::Malformed)?;
        url.query_pairs_mut()
            .append_pair("startHistoryId", start)
            .append_pair("maxResults", &MAX_LIST_RESULTS.to_string());
        for kind in [
            "messageAdded",
            "messageDeleted",
            "labelAdded",
            "labelRemoved",
        ] {
            url.query_pairs_mut().append_pair("historyTypes", kind);
        }
        if let Some(page) = page_token {
            if !valid_page_token(page) {
                return Err(GoogleApiError::Malformed);
            }
            url.query_pairs_mut().append_pair("pageToken", page);
        }
        let json = self.gmail_get(url, access, MAX_HISTORY_BYTES).await?;
        parse_history(&json)
    }

    /// Asks Gmail to notify `topic` of every change to the mailbox
    /// (`users.watch`). Renewing replaces the old watch. The topic is fixed
    /// configuration, never request input.
    pub async fn watch(&self, access: &Secret, topic: &str) -> Result<Watch, GoogleApiError> {
        let url = self
            .gmail_api
            .join("watch")
            .map_err(|_| GoogleApiError::Malformed)?;
        let body = serde_json::json!({ "topicName": topic });
        let resp = self
            .http
            .post(url)
            .bearer_auth(access.expose())
            .json(&body)
            .send()
            .await
            .map_err(unreachable)?;
        let status = resp.status();
        if status.as_u16() == 401 {
            return Err(GoogleApiError::Revoked);
        }
        if !status.is_success() {
            return Err(GoogleApiError::Status(
                status.as_u16(),
                error_reason(resp).await,
            ));
        }
        let json = read_json(resp, MAX_RESPONSE_BYTES).await?;
        history_id_field(&json)?;
        let millis: i64 = json
            .get("expiration")
            .and_then(Value::as_str)
            .and_then(|e| e.parse().ok())
            .ok_or(GoogleApiError::Malformed)?;
        let expires_at =
            time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(millis) * 1_000_000)
                .map_err(|_| GoogleApiError::Malformed)?;
        Ok(Watch { expires_at })
    }

    /// Stops the mailbox's notifications (`users.stop`).
    pub async fn stop_watch(&self, access: &Secret) -> Result<(), GoogleApiError> {
        let url = self
            .gmail_api
            .join("stop")
            .map_err(|_| GoogleApiError::Malformed)?;
        let resp = self
            .http
            .post(url)
            .bearer_auth(access.expose())
            .send()
            .await
            .map_err(unreachable)?;
        let status = resp.status();
        if status.as_u16() == 401 {
            return Err(GoogleApiError::Revoked);
        }
        if status.is_success() {
            Ok(())
        } else {
            Err(GoogleApiError::Status(status.as_u16(), None))
        }
    }

    /// Checks the token a Pub/Sub push request carries: signed by Google
    /// (RS256, one of Google's published keys), for our subscription's
    /// audience, by the service account the subscription signs as, and
    /// current. The request came from the internet, so unlike sign-in's ID
    /// token the signature is what proves it came from Google.
    pub async fn verify_push_token(
        &self,
        token: &str,
        expect: &PushExpectation<'_>,
    ) -> Result<(), PushRejected> {
        let kid = token_key_id(token)?;
        let key = match self.cached_key(&kid) {
            Ok(key) => key,
            Err(refetch) => {
                if refetch {
                    let keys = self.fetch_keys().await?;
                    let mut cache = self.keys.lock().map_err(|_| PushRejected::UnknownKey)?;
                    cache.keys = keys;
                    cache.fetched = Some(Instant::now());
                }
                self.cached_key(&kid)
                    .map_err(|_| PushRejected::UnknownKey)?
            }
        };
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        verify_push_jwt(token, &kid, &key, expect, now)
    }

    /// The cached key `kid`, or whether the keys should be fetched (they are
    /// stale, or `kid` is new and the last fetch wasn't just now).
    fn cached_key(&self, kid: &str) -> Result<SigningKey, bool> {
        let Ok(cache) = self.keys.lock() else {
            return Err(false);
        };
        let age = cache.fetched.map(|t| t.elapsed());
        let fresh = age.is_some_and(|a| a < KEYS_TTL);
        match cache.keys.get(kid) {
            Some(key) if fresh => Ok(key.clone()),
            _ => Err(!fresh || age.is_none_or(|a| a >= KEYS_REFETCH_GAP)),
        }
    }

    async fn fetch_keys(&self) -> Result<HashMap<String, SigningKey>, PushRejected> {
        let failed = |e: String| PushRejected::KeysUnavailable(e);
        let resp = self
            .http
            .get(self.certs_endpoint.clone())
            .send()
            .await
            .map_err(|e| failed(e.without_url().to_string()))?;
        if !resp.status().is_success() {
            return Err(failed(format!("HTTP {}", resp.status().as_u16())));
        }
        let json = read_json(resp, MAX_RESPONSE_BYTES)
            .await
            .map_err(|_| failed("unreadable key set".into()))?;
        let keys = parse_keys(&json);
        if keys.is_empty() {
            return Err(failed("empty key set".into()));
        }
        Ok(keys)
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
            Err(GoogleApiError::Status(status.as_u16(), None))
        }
    }
}

/// The `historyId` of a profile or watch response.
fn history_id_field(json: &Value) -> Result<String, GoogleApiError> {
    json.get("historyId")
        .and_then(|h| match h {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => n.as_u64().map(|n| n.to_string()),
            _ => None,
        })
        .filter(|h| valid_history_id(h))
        .ok_or(GoogleApiError::Malformed)
}

/// Reads one `users.history.list` page. Message and label IDs that aren't
/// plain IDs are dropped, like everywhere else Gmail IDs are read.
fn parse_history(json: &Value) -> Result<HistoryPage, GoogleApiError> {
    let history_id = history_id_field(json)?;
    let next = match json.get("nextPageToken") {
        None => None,
        Some(t) => Some(
            t.as_str()
                .filter(|t| valid_page_token(t))
                .ok_or(GoogleApiError::Malformed)?
                .to_owned(),
        ),
    };
    let records = match json.get("history") {
        None => &Vec::new(),
        Some(h) => h.as_array().ok_or(GoogleApiError::Malformed)?,
    };
    let message_id = |entry: &Value| -> Option<String> {
        entry
            .get("message")?
            .get("id")?
            .as_str()
            .filter(|id| valid_gmail_id(id))
            .map(str::to_owned)
    };
    let label_ids = |entry: &Value| -> Vec<String> {
        entry
            .get("labelIds")
            .and_then(Value::as_array)
            .map(|ls| {
                ls.iter()
                    .filter_map(Value::as_str)
                    .filter(|l| valid_label_id(l))
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    };
    let entries = |record: &Value, key: &str| -> Vec<Value> {
        record
            .get(key)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    let mut changes = Vec::new();
    for record in records {
        for e in entries(record, "messagesAdded") {
            changes.extend(message_id(&e).map(HistoryChange::Added));
        }
        for e in entries(record, "messagesDeleted") {
            changes.extend(message_id(&e).map(HistoryChange::Deleted));
        }
        for e in entries(record, "labelsAdded") {
            changes.extend(message_id(&e).map(|id| HistoryChange::LabelsAdded(id, label_ids(&e))));
        }
        for e in entries(record, "labelsRemoved") {
            changes
                .extend(message_id(&e).map(|id| HistoryChange::LabelsRemoved(id, label_ids(&e))));
        }
    }
    Ok(HistoryPage {
        changes,
        next,
        history_id,
    })
}

/// Google's RSA signing keys from a JWKS document, by key ID. Keys that
/// aren't RS256 RSA keys of at least 2048 bits are left out.
fn parse_keys(json: &Value) -> HashMap<String, SigningKey> {
    let Some(keys) = json.get("keys").and_then(Value::as_array) else {
        return HashMap::new();
    };
    keys.iter()
        .filter_map(|k| {
            if k.get("kty").and_then(Value::as_str) != Some("RSA") {
                return None;
            }
            if k.get("alg")
                .and_then(Value::as_str)
                .is_some_and(|a| a != "RS256")
            {
                return None;
            }
            let kid = k
                .get("kid")?
                .as_str()
                .filter(|kid| (1..=128).contains(&kid.len()))?;
            let n = URL_SAFE_NO_PAD.decode(k.get("n")?.as_str()?).ok()?;
            let e = URL_SAFE_NO_PAD.decode(k.get("e")?.as_str()?).ok()?;
            let n: Vec<u8> = n.into_iter().skip_while(|b| *b == 0).collect();
            (n.len() >= 256).then(|| (kid.to_owned(), SigningKey { n, e }))
        })
        .collect()
}

/// The decoded header of a JWT, refused unless it is RS256 with a key ID.
fn token_key_id(token: &str) -> Result<String, PushRejected> {
    let header = token.split('.').next().ok_or(PushRejected::Malformed)?;
    let header: Value = URL_SAFE_NO_PAD
        .decode(header)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or(PushRejected::Malformed)?;
    if header.get("alg").and_then(Value::as_str) != Some("RS256") {
        return Err(PushRejected::Algorithm);
    }
    header
        .get("kid")
        .and_then(Value::as_str)
        .filter(|kid| (1..=128).contains(&kid.len()))
        .map(str::to_owned)
        .ok_or(PushRejected::Malformed)
}

/// Checks a push token's signature with `key` and its claims: Google's
/// issuer, our audience, the subscription's service account with a
/// verified email, and not expired or issued in the future.
fn verify_push_jwt(
    token: &str,
    kid: &str,
    key: &SigningKey,
    expect: &PushExpectation<'_>,
    now: i64,
) -> Result<(), PushRejected> {
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(PushRejected::Malformed);
    };
    if token_key_id(token)? != kid {
        return Err(PushRejected::UnknownKey);
    }
    let sig = URL_SAFE_NO_PAD
        .decode(sig)
        .map_err(|_| PushRejected::Malformed)?;
    let signed = &token[..header.len() + 1 + payload.len()];
    ring::signature::RsaPublicKeyComponents {
        n: &key.n[..],
        e: &key.e[..],
    }
    .verify(
        &ring::signature::RSA_PKCS1_2048_8192_SHA256,
        signed.as_bytes(),
        &sig,
    )
    .map_err(|_| PushRejected::Signature)?;

    let claims: Value = URL_SAFE_NO_PAD
        .decode(payload)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or(PushRejected::Malformed)?;
    let str_claim = |name: &'static str| {
        claims
            .get(name)
            .and_then(Value::as_str)
            .ok_or(PushRejected::InvalidClaim(name))
    };
    let int_claim = |name: &'static str| {
        claims
            .get(name)
            .and_then(Value::as_i64)
            .ok_or(PushRejected::InvalidClaim(name))
    };
    let iss = str_claim("iss")?;
    if iss != ISSUER && iss != ISSUER_SHORT {
        return Err(PushRejected::InvalidClaim("iss"));
    }
    if !ct_eq(str_claim("aud")?, expect.audience) {
        return Err(PushRejected::InvalidClaim("aud"));
    }
    if !str_claim("email")?.eq_ignore_ascii_case(expect.service_account) {
        return Err(PushRejected::InvalidClaim("email"));
    }
    if claims.get("email_verified") != Some(&Value::Bool(true)) {
        return Err(PushRejected::InvalidClaim("email_verified"));
    }
    if int_claim("exp")? + CLOCK_SKEW_SECS <= now {
        return Err(PushRejected::InvalidClaim("exp"));
    }
    if int_claim("iat")? - CLOCK_SKEW_SECS > now {
        return Err(PushRejected::InvalidClaim("iat"));
    }
    Ok(())
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
        // Page tokens go into the list query and the database.
        assert!(valid_page_token("09876543210987654321"));
        for bad in [
            "",
            "a&maxResults=1",
            "a b",
            "a/b",
            "a%26b",
            &"1".repeat(257),
        ] {
            assert!(!valid_page_token(bad), "accepted {bad:?}");
        }
        // Label IDs go into the list query; user labels look like Label_12.
        for good in ["INBOX", "CATEGORY_UPDATES", "Label_12"] {
            assert!(valid_label_id(good), "{good}");
        }
        assert!(valid_user_label_id("Label_12") && !valid_user_label_id("INBOX"));
        for bad in [
            "",
            "Label_",
            "Label_../x",
            "Label_1&x=y",
            "a b",
            &"a".repeat(81),
        ] {
            assert!(
                !valid_label_id(bad) || !valid_user_label_id(bad),
                "accepted {bad:?}"
            );
        }
        assert!(!valid_label_id("Label_1&x=y") && !valid_label_id("../x"));
        // Attachment IDs are long base64url; still nothing that changes the path.
        assert!(valid_attachment_id("ANGjdJ8w-x_Yz09"));
        for bad in [
            "",
            "../x",
            "a/b",
            "a?b",
            "a%2Fb",
            "a=",
            "a b",
            &"a".repeat(2049),
        ] {
            assert!(!valid_attachment_id(bad), "accepted {bad:?}");
        }
    }

    // ---- Pub/Sub push tokens ----------------------------------------------

    /// A throwaway RSA key, made for these tests only (see
    /// docs/casa/exceptions.md). It plays Google's signing key.
    const TEST_SIGNER: &[u8] = include_bytes!("testdata/push_signer.pk8");
    pub(crate) const TEST_KID: &str = "test-signing-key";

    fn signer() -> ring::rsa::KeyPair {
        ring::rsa::KeyPair::from_pkcs8(TEST_SIGNER).unwrap()
    }

    /// The JWKS document Google would publish for the test key.
    pub(crate) fn test_jwks() -> Value {
        let public: ring::rsa::PublicKeyComponents<Vec<u8>> = signer().public().into();
        json!({ "keys": [{
            "kty": "RSA", "alg": "RS256", "use": "sig", "kid": TEST_KID,
            "n": URL_SAFE_NO_PAD.encode(&public.n),
            "e": URL_SAFE_NO_PAD.encode(&public.e),
        }]})
    }

    /// A token signed with the test key, with `header` and `claims`.
    pub(crate) fn sign_token(header: &Value, claims: &Value) -> String {
        let enc = |v: &Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap());
        let signed = format!("{}.{}", enc(header), enc(claims));
        let pair = signer();
        let mut sig = vec![0; pair.public().modulus_len()];
        pair.sign(
            &ring::signature::RSA_PKCS1_SHA256,
            &ring::rand::SystemRandom::new(),
            signed.as_bytes(),
            &mut sig,
        )
        .unwrap();
        format!("{signed}.{}", URL_SAFE_NO_PAD.encode(sig))
    }

    pub(crate) const PUSH_AUDIENCE: &str = "https://hadal.example.com/api/gmail/push";
    pub(crate) const PUSH_ACCOUNT: &str = "pubsub-push@hadal-test.iam.gserviceaccount.com";

    pub(crate) fn push_claims(now: i64) -> Value {
        json!({
            "iss": ISSUER,
            "aud": PUSH_AUDIENCE,
            "email": PUSH_ACCOUNT,
            "email_verified": true,
            "sub": "1234567890",
            "iat": now,
            "exp": now + 3600,
        })
    }

    pub(crate) fn push_token(now: i64) -> String {
        sign_token(
            &json!({"alg": "RS256", "kid": TEST_KID, "typ": "JWT"}),
            &push_claims(now),
        )
    }

    fn check_push(token: &str) -> Result<(), PushRejected> {
        let keys = parse_keys(&test_jwks());
        let kid = token_key_id(token)?;
        let key = keys.get(&kid).ok_or(PushRejected::UnknownKey)?;
        let expect = PushExpectation {
            audience: PUSH_AUDIENCE,
            service_account: PUSH_ACCOUNT,
        };
        verify_push_jwt(token, &kid, key, &expect, NOW)
    }

    #[test]
    fn push_tokens_must_be_signed_by_google_for_our_subscription() {
        // CASA 3.1.1 / 2.1.1: the push endpoint has no session, so the
        // signed token is what lets a request in. Each check fails alone.
        check_push(&push_token(NOW)).unwrap();
        let header = json!({"alg": "RS256", "kid": TEST_KID});
        let cases: [(&str, Value); 8] = [
            ("iss", json!("https://evil.example.com")),
            ("aud", json!("https://evil.example.com/api/gmail/push")),
            ("email", json!("attacker@evil.iam.gserviceaccount.com")),
            ("email_verified", json!(false)),
            ("email_verified", json!("true")),
            ("exp", json!(NOW - 3600)),
            ("iat", json!(NOW + 3600)),
            ("aud", json!([PUSH_AUDIENCE])),
        ];
        for (claim, value) in cases {
            let mut c = push_claims(NOW);
            c[claim] = value.clone();
            assert!(
                check_push(&sign_token(&header, &c)).is_err(),
                "accepted {claim}={value}"
            );
        }
        for claim in ["iss", "aud", "email", "email_verified", "exp", "iat"] {
            let mut c = push_claims(NOW);
            c.as_object_mut().unwrap().remove(claim);
            assert!(
                check_push(&sign_token(&header, &c)).is_err(),
                "accepted missing {claim}"
            );
        }
    }

    #[test]
    fn push_tokens_with_forged_signatures_or_algorithms_are_refused() {
        let good = push_token(NOW);
        let (signed, sig) = good.rsplit_once('.').unwrap();
        // Claims changed after signing.
        let (header, _) = signed.split_once('.').unwrap();
        let mut c = push_claims(NOW);
        c["email"] = json!("attacker@evil.iam.gserviceaccount.com");
        let swapped = format!(
            "{header}.{}.{sig}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&c).unwrap())
        );
        assert!(matches!(check_push(&swapped), Err(PushRejected::Signature)));
        // No signature, or a mangled one.
        assert!(check_push(&format!("{signed}.")).is_err());
        let mut bytes = URL_SAFE_NO_PAD.decode(sig).unwrap();
        bytes[0] ^= 1;
        let flipped = format!("{signed}.{}", URL_SAFE_NO_PAD.encode(bytes));
        assert!(matches!(check_push(&flipped), Err(PushRejected::Signature)));
        // alg "none" or an HMAC, even with a real key ID.
        for alg in ["none", "HS256", "RS512"] {
            let header = json!({"alg": alg, "kid": TEST_KID});
            let enc = |v: &Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap());
            let forged = format!("{}.{}.", enc(&header), enc(&push_claims(NOW)));
            assert!(
                matches!(check_push(&forged), Err(PushRejected::Algorithm)),
                "{alg}"
            );
        }
        // A key we don't have.
        let other = sign_token(&json!({"alg": "RS256", "kid": "other"}), &push_claims(NOW));
        assert!(matches!(check_push(&other), Err(PushRejected::UnknownKey)));
        for bad in ["", "a", "a.b", "a.b.c.d", "!!.b.c"] {
            assert!(check_push(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn only_strong_rsa_keys_are_kept_from_the_key_set() {
        let mut jwks = test_jwks();
        let good = jwks["keys"][0].clone();
        let mut short = good.clone();
        short["kid"] = json!("short");
        short["n"] = json!(URL_SAFE_NO_PAD.encode([0xff; 128]));
        let mut ec = good.clone();
        ec["kid"] = json!("ec");
        ec["kty"] = json!("EC");
        let mut hs = good.clone();
        hs["kid"] = json!("hs");
        hs["alg"] = json!("HS256");
        jwks["keys"] = json!([good, short, ec, hs, {"kid": "junk"}]);
        let keys = parse_keys(&jwks);
        assert_eq!(keys.keys().collect::<Vec<_>>(), [TEST_KID]);
    }

    #[test]
    fn history_pages_are_read_in_order_with_ids_checked() {
        let page = parse_history(&json!({
            "historyId": "905",
            "nextPageToken": "abc123",
            "history": [
                {"id": "901", "messagesAdded": [{"message": {"id": "m1", "labelIds": ["INBOX"]}}]},
                {"id": "902", "labelsAdded": [{"message": {"id": "m0"}, "labelIds": ["STARRED", "a/b"]}]},
                {"id": "903", "labelsRemoved": [{"message": {"id": "m0"}, "labelIds": ["UNREAD"]}]},
                {"id": "904", "messagesDeleted": [{"message": {"id": "m2"}}, {"message": {"id": "../x"}}]},
            ],
        }))
        .unwrap();
        assert_eq!(page.history_id, "905");
        assert_eq!(page.next.as_deref(), Some("abc123"));
        assert_eq!(
            page.changes,
            [
                HistoryChange::Added("m1".into()),
                HistoryChange::LabelsAdded("m0".into(), vec!["STARRED".into()]),
                HistoryChange::LabelsRemoved("m0".into(), vec!["UNREAD".into()]),
                HistoryChange::Deleted("m2".into()),
            ]
        );
        // No changes: no `history` key at all.
        let empty = parse_history(&json!({"historyId": "7"})).unwrap();
        assert!(empty.changes.is_empty() && empty.next.is_none());
        for bad in [
            json!({}),
            json!({"historyId": "12a"}),
            json!({"historyId": "1", "nextPageToken": "a&b"}),
            json!({"historyId": "1", "history": {}}),
        ] {
            assert!(parse_history(&bad).is_err(), "accepted {bad}");
        }
        assert!(valid_history_id("18446744073709551615"));
        assert!(!valid_history_id("") && !valid_history_id("1".repeat(21).as_str()));
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
