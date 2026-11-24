use std::num::NonZeroU32;

use anyhow::{Context, Result, bail};
use reqwest::Url;

/// A value that must never be logged. `Debug` prints `<redacted>`, and there is
/// no `Display`, so it can't end up in a log line or `format!` by accident.
#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Longest session we will ever issue. CASA 2.2.3 caps token lifetime at 24h.
pub const MAX_SESSION_ABSOLUTE_SECS: u32 = 24 * 60 * 60;

#[derive(Clone, Debug)]
pub struct OAuthConfig {
    pub client_id: String,
    pub client_secret: Secret,
    /// Fixed and registered in the Google console (CASA 3.2.2). Never taken
    /// from the request.
    pub redirect_uri: Url,
}

#[derive(Clone, Debug)]
pub struct SessionConfig {
    /// Session ends after this long without a request.
    pub idle_secs: u32,
    /// Session ends this long after sign-in, however active.
    pub absolute_secs: u32,
}

#[derive(Clone)]
pub struct Config {
    pub database_url: Secret,
    pub host: String,
    pub port: u16,
    pub db_max_connections: u32,
    pub rate_limit_per_second: NonZeroU32,
    pub rate_limit_burst: NonZeroU32,
    pub auth_rate_limit_per_minute: NonZeroU32,
    pub auth_rate_limit_burst: NonZeroU32,
    pub trust_proxy_headers: bool,
    pub oauth: OAuthConfig,
    pub session: SessionConfig,
    /// Base64 AES-256 key for Google refresh tokens and imported mail
    /// (`crypto::DataCipher`).
    pub data_encryption_key: Secret,
}

// Hand-written so the connection string (which carries the DB password) can
// never end up in logs via `{:?}` (ASVS V7.1.1).
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("database_url", &self.database_url)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("db_max_connections", &self.db_max_connections)
            .field("rate_limit_per_second", &self.rate_limit_per_second)
            .field("rate_limit_burst", &self.rate_limit_burst)
            .field(
                "auth_rate_limit_per_minute",
                &self.auth_rate_limit_per_minute,
            )
            .field("auth_rate_limit_burst", &self.auth_rate_limit_burst)
            .field("trust_proxy_headers", &self.trust_proxy_headers)
            .field("oauth", &self.oauth)
            .field("session", &self.session)
            .field("data_encryption_key", &self.data_encryption_key)
            .finish()
    }
}

fn env_or<T: std::str::FromStr>(key: &str, default: &str) -> Result<T>
where
    T::Err: std::error::Error + Send + Sync + 'static,
{
    std::env::var(key)
        .unwrap_or_else(|_| default.into())
        .parse()
        .with_context(|| format!("{key} is invalid"))
}

fn required(key: &str) -> Result<String> {
    match std::env::var(key) {
        Ok(v) if !v.trim().is_empty() => Ok(v),
        _ => bail!("{key} must be set"),
    }
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let oauth = OAuthConfig {
            client_id: required("GOOGLE_CLIENT_ID")?,
            client_secret: Secret::new(required("GOOGLE_CLIENT_SECRET")?),
            redirect_uri: Url::parse(&required("OAUTH_REDIRECT_URI")?)
                .context("OAUTH_REDIRECT_URI is not a valid URL")?,
        };
        let session = SessionConfig {
            idle_secs: env_or("SESSION_IDLE_SECS", "1800")?,
            absolute_secs: env_or("SESSION_ABSOLUTE_SECS", "43200")?,
        };
        let cfg = Self {
            database_url: Secret::new(
                std::env::var("DATABASE_URL").context("DATABASE_URL must be set")?,
            ),
            host: std::env::var("APP_HOST").unwrap_or_else(|_| "0.0.0.0".into()),
            port: env_or("APP_PORT", "8080")?,
            db_max_connections: env_or("DB_MAX_CONNECTIONS", "10")?,
            rate_limit_per_second: env_or("RATE_LIMIT_PER_SECOND", "10")?,
            rate_limit_burst: env_or("RATE_LIMIT_BURST", "30")?,
            auth_rate_limit_per_minute: env_or("AUTH_RATE_LIMIT_PER_MINUTE", "10")?,
            auth_rate_limit_burst: env_or("AUTH_RATE_LIMIT_BURST", "5")?,
            trust_proxy_headers: env_or("TRUST_PROXY_HEADERS", "false")?,
            oauth,
            session,
            data_encryption_key: Secret::new(required("DATA_ENCRYPTION_KEY")?),
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// Refuse to start with settings that would weaken auth.
    pub fn validate(&self) -> Result<()> {
        validate_redirect_uri(&self.oauth.redirect_uri)?;
        validate_database_tls(self.database_url.expose())?;
        crate::crypto::DataCipher::from_base64(self.data_encryption_key.expose())?;
        let s = &self.session;
        if s.idle_secs == 0 || s.absolute_secs == 0 {
            bail!("session lifetimes must be non-zero");
        }
        if s.absolute_secs > MAX_SESSION_ABSOLUTE_SECS {
            bail!("SESSION_ABSOLUTE_SECS must be at most {MAX_SESSION_ABSOLUTE_SECS} (24h)");
        }
        if s.idle_secs > s.absolute_secs {
            bail!("SESSION_IDLE_SECS must not exceed SESSION_ABSOLUTE_SECS");
        }
        Ok(())
    }
}

/// The redirect URI must be https (plain http only for a loopback dev host),
/// carry no query or fragment, and point at our callback route.
fn validate_redirect_uri(uri: &Url) -> Result<()> {
    let loopback = matches!(uri.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    match uri.scheme() {
        "https" => {}
        "http" if loopback => {}
        _ => bail!("OAUTH_REDIRECT_URI must use https (http is allowed only for localhost)"),
    }
    if uri.query().is_some() || uri.fragment().is_some() {
        bail!("OAUTH_REDIRECT_URI must not have a query or fragment");
    }
    if uri.path() != "/api/auth/callback" {
        bail!("OAUTH_REDIRECT_URI must end in /api/auth/callback");
    }
    Ok(())
}

/// Any database that isn't on this machine must be reached over TLS with the
/// certificate and host name verified (`sslmode=verify-full`, CASA 4.1.2).
/// Only a loopback database may skip it. The URL is never echoed in errors.
fn validate_database_tls(raw: &str) -> Result<()> {
    let Ok(url) = Url::parse(raw) else {
        bail!("DATABASE_URL is not a valid URL");
    };
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    let mode = url
        .query_pairs()
        .filter(|(k, _)| k == "sslmode" || k == "ssl-mode")
        .map(|(_, v)| v.to_ascii_lowercase())
        .last();
    if !loopback && mode.as_deref() != Some("verify-full") {
        bail!("DATABASE_URL must use sslmode=verify-full for a non-local database");
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn test_config() -> Config {
        Config {
            database_url: Secret::new("postgres://hadal:s3cret-pw@db/hadal?sslmode=verify-full"),
            host: "0.0.0.0".into(),
            port: 8080,
            db_max_connections: 10,
            rate_limit_per_second: NonZeroU32::new(10).unwrap(),
            rate_limit_burst: NonZeroU32::new(30).unwrap(),
            auth_rate_limit_per_minute: NonZeroU32::new(10).unwrap(),
            auth_rate_limit_burst: NonZeroU32::new(5).unwrap(),
            trust_proxy_headers: false,
            oauth: OAuthConfig {
                client_id: "test-client.apps.googleusercontent.com".into(),
                client_secret: Secret::new("oauth-s3cret-value"),
                redirect_uri: Url::parse("http://localhost:8000/api/auth/callback").unwrap(),
            },
            session: SessionConfig {
                idle_secs: 1800,
                absolute_secs: 43200,
            },
            data_encryption_key: Secret::new(crate::crypto::tests::test_key()),
        }
    }

    #[test]
    fn debug_output_redacts_secrets() {
        let out = format!("{:?}", test_config());
        let key = crate::crypto::tests::test_key();
        for secret in ["s3cret-pw", "oauth-s3cret-value", key.as_str()] {
            assert!(!out.contains(secret), "secret leaked into Debug: {out}");
        }
        assert!(out.contains("<redacted>"));
    }

    #[test]
    fn default_config_is_valid() {
        test_config().validate().unwrap();
    }

    #[test]
    fn redirect_uri_must_be_https_fixed_and_exact() {
        // CASA 3.2.2 / 4.1.1.
        for bad in [
            "http://hadal.example.com/api/auth/callback",
            "https://hadal.example.com/api/auth/callback?next=/evil",
            "https://hadal.example.com/api/auth/callback#x",
            "https://hadal.example.com/other",
            "javascript:alert(1)",
        ] {
            let mut cfg = test_config();
            cfg.oauth.redirect_uri = Url::parse(bad).unwrap();
            assert!(cfg.validate().is_err(), "accepted {bad}");
        }
        let mut cfg = test_config();
        cfg.oauth.redirect_uri = Url::parse("https://hadal.example.com/api/auth/callback").unwrap();
        cfg.validate().unwrap();
    }

    #[test]
    fn remote_database_requires_verified_tls() {
        // CASA 4.1.2: no plaintext or unverified TLS to a database elsewhere.
        for bad in [
            "postgres://u@db/hadal",
            "postgres://u@db/hadal?sslmode=require",
            "postgres://u@db/hadal?sslmode=verify-ca",
            "postgres://u@db.example.com/hadal?sslmode=disable",
            "postgres://u@db/hadal?sslmode=verify-full&sslmode=prefer",
            "not a url",
        ] {
            assert!(validate_database_tls(bad).is_err(), "accepted {bad}");
        }
        for good in [
            "postgres://u@db/hadal?sslmode=verify-full&sslrootcert=/etc/hadal/db-ca.crt",
            "postgres://u@db.example.com/hadal?ssl-mode=VERIFY-FULL",
            "postgres://u@127.0.0.1:55432/hadal_test",
            "postgres://u@localhost/hadal",
        ] {
            validate_database_tls(good).unwrap();
        }
        // The error never contains the URL (it holds the password).
        let err = validate_database_tls("postgres://u:pw-in-url@db/hadal").unwrap_err();
        assert!(!err.to_string().contains("pw-in-url"));
    }

    #[test]
    fn data_encryption_key_must_be_a_valid_aes_256_key() {
        let mut cfg = test_config();
        cfg.data_encryption_key = Secret::new("too-short");
        let err = cfg.validate().unwrap_err();
        assert!(!err.to_string().contains("too-short"), "key echoed: {err}");
    }

    #[test]
    fn session_lifetime_is_capped_at_24_hours() {
        // CASA 2.2.3.
        let mut cfg = test_config();
        cfg.session.absolute_secs = MAX_SESSION_ABSOLUTE_SECS + 1;
        assert!(cfg.validate().is_err());
        let mut cfg = test_config();
        cfg.session.idle_secs = 0;
        assert!(cfg.validate().is_err());
        let mut cfg = test_config();
        cfg.session.idle_secs = cfg.session.absolute_secs + 1;
        assert!(cfg.validate().is_err());
    }
}
