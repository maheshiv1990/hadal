use std::num::NonZeroU32;

use anyhow::{Context, Result};

#[derive(Clone)]
pub struct Config {
    pub database_url: String,
    pub host: String,
    pub port: u16,
    pub db_max_connections: u32,
    pub rate_limit_per_second: NonZeroU32,
    pub rate_limit_burst: NonZeroU32,
    pub trust_proxy_headers: bool,
}

// Hand-written so the connection string (which carries the DB password) can
// never end up in logs via `{:?}` (ASVS V7.1.1).
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("database_url", &"<redacted>")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("db_max_connections", &self.db_max_connections)
            .field("rate_limit_per_second", &self.rate_limit_per_second)
            .field("rate_limit_burst", &self.rate_limit_burst)
            .field("trust_proxy_headers", &self.trust_proxy_headers)
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

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            database_url: std::env::var("DATABASE_URL").context("DATABASE_URL must be set")?,
            host: std::env::var("APP_HOST").unwrap_or_else(|_| "0.0.0.0".into()),
            port: env_or("APP_PORT", "8080")?,
            db_max_connections: env_or("DB_MAX_CONNECTIONS", "10")?,
            rate_limit_per_second: env_or("RATE_LIMIT_PER_SECOND", "10")?,
            rate_limit_burst: env_or("RATE_LIMIT_BURST", "30")?,
            trust_proxy_headers: env_or("TRUST_PROXY_HEADERS", "false")?,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_redacts_database_url() {
        let cfg = Config {
            database_url: "postgres://hadal:s3cret-pw@db/hadal".into(),
            host: "0.0.0.0".into(),
            port: 8080,
            db_max_connections: 10,
            rate_limit_per_second: NonZeroU32::new(10).unwrap(),
            rate_limit_burst: NonZeroU32::new(30).unwrap(),
            trust_proxy_headers: false,
        };
        let out = format!("{cfg:?}");
        assert!(
            !out.contains("s3cret-pw"),
            "secret leaked into Debug: {out}"
        );
        assert!(out.contains("<redacted>"));
    }
}
