//! Email + password accounts (CASA 1.1.1, 1.1.3, 6.5.1).
//!
//! These are separate from Google accounts. An address registered here is
//! never linked to a Google sign-in with the same address, because
//! registration emails aren't verified yet.
//!
//! - Passwords are hashed with Argon2id at OWASP's parameters on a blocking
//!   thread and never stored, logged or echoed back. The request types don't
//!   derive `Debug`, so they can't end up in a log by accident.
//! - A failed sign-in always says "invalid email or password", and an unknown
//!   email still costs one Argon2 verification, so neither the message nor the
//!   timing tells whether the account exists.
//! - Sign-in attempts are limited per IP (`AuthLimiter`) and per account
//!   (`AccountLimiter`), so a distributed guessing run is also slowed down.

use std::num::NonZeroU32;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use actix_web::{HttpRequest, HttpResponse, http::StatusCode, web};
use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHasher, PasswordVerifier},
};
use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use serde::Deserialize;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use super::token::random_token;
use crate::config::SessionConfig;
use crate::error::AppError;

/// NIST SP 800-63B / ASVS 2.1: at least 12 characters, long passphrases
/// allowed, no composition rules.
pub const MIN_PASSWORD_CHARS: usize = 12;
pub const MAX_PASSWORD_CHARS: usize = 128;
const MAX_NAME_CHARS: usize = 100;
/// RFC 5321 path limit.
const MAX_EMAIL_LEN: usize = 254;
const MAX_EMAIL_LOCAL_LEN: usize = 64;

/// Argon2id with OWASP's minimum (19 MiB, 2 passes, 1 lane), pinned here so a
/// change in the crate's defaults can't weaken it.
fn argon2() -> Result<Argon2<'static>, AppError> {
    let params = Params::new(19 * 1024, 2, 1, None)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("argon2 params: {e}")))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Hashes a password to a PHC string with a fresh 128-bit salt.
pub fn hash_password(password: &str) -> Result<String, AppError> {
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("OS random source failed: {e}")))?;
    let hash = argon2()?
        .hash_password_with_salt(password.as_bytes(), &salt)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("argon2 hashing failed: {e}")))?;
    Ok(hash.to_string())
}

/// True only if `password` matches the stored PHC string. A malformed hash
/// counts as a mismatch.
pub fn verify_password(password: &str, stored: &str) -> bool {
    argon2().is_ok_and(|a| a.verify_password(password.as_bytes(), stored).is_ok())
}

/// A hash of a random secret, checked when the email is unknown so that the
/// response takes as long as for a real account.
fn dummy_hash() -> Result<&'static str, AppError> {
    static DUMMY: OnceLock<String> = OnceLock::new();
    if let Some(h) = DUMMY.get() {
        return Ok(h);
    }
    let h = hash_password(&random_token()?)?;
    Ok(DUMMY.get_or_init(|| h))
}

fn clean_name(field: &str, raw: &str) -> Result<String, AppError> {
    let name = raw.trim();
    let len = name.chars().count();
    if len == 0 || len > MAX_NAME_CHARS || name.chars().any(char::is_control) {
        return Err(AppError::BadRequest(format!(
            "{field} must be 1-{MAX_NAME_CHARS} characters"
        )));
    }
    Ok(name.to_owned())
}

/// Lower-cases and checks the shape of an address. Deliberately simple: the
/// only real check of an address is sending mail to it.
pub fn normalize_email(raw: &str) -> Result<String, AppError> {
    let invalid = || AppError::BadRequest("enter a valid email address".into());
    let email = raw.trim().to_lowercase();
    if email.len() > MAX_EMAIL_LEN
        || email
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || "<>()[],;:\\\"".contains(c))
    {
        return Err(invalid());
    }
    let (local, domain) = email.split_once('@').ok_or_else(invalid)?;
    let domain_ok = domain.contains('.')
        && !domain.contains('@')
        && !domain.starts_with(['.', '-'])
        && !domain.ends_with(['.', '-'])
        && !domain.contains("..");
    if local.is_empty() || local.len() > MAX_EMAIL_LOCAL_LEN || !domain_ok {
        return Err(invalid());
    }
    Ok(email)
}

pub fn check_password_policy(password: &str, email: &str) -> Result<(), AppError> {
    let len = password.chars().count();
    if !(MIN_PASSWORD_CHARS..=MAX_PASSWORD_CHARS).contains(&len) {
        return Err(AppError::BadRequest(format!(
            "password must be {MIN_PASSWORD_CHARS}-{MAX_PASSWORD_CHARS} characters"
        )));
    }
    if password.trim().is_empty() || password.to_lowercase() == email {
        return Err(AppError::BadRequest(
            "choose a password that isn't blank or your email".into(),
        ));
    }
    Ok(())
}

/// Per-account limit on sign-in attempts, keyed by the normalized email
/// whether or not the account exists (so a 429 reveals nothing): 10 attempts,
/// then one every 3 minutes.
#[derive(Clone)]
pub struct AccountLimiter(Arc<DefaultKeyedRateLimiter<String>>);

impl AccountLimiter {
    pub fn new() -> Self {
        Self::with(Duration::from_secs(180), 10)
    }

    /// One attempt per `period` after an initial `burst`.
    pub fn with(period: Duration, burst: u32) -> Self {
        let burst = NonZeroU32::new(burst).unwrap_or(NonZeroU32::MIN);
        // `with_period` is only `None` for a zero period; fall back to the strictest.
        let quota = Quota::with_period(period)
            .unwrap_or_else(|| Quota::per_hour(NonZeroU32::MIN))
            .allow_burst(burst);
        Self(Arc::new(RateLimiter::keyed(quota)))
    }

    fn allow(&self, email: &str) -> bool {
        self.0.check_key(&email.to_owned()).is_ok()
    }

    pub fn housekeep(&self) {
        self.0.retain_recent();
        self.0.shrink_to_fit();
    }
}

fn blocking_failed(e: actix_web::error::BlockingError) -> AppError {
    AppError::Internal(anyhow::anyhow!("blocking task failed: {e}"))
}

/// `POST /api/auth/register`. Confirming the password is the form's job; the
/// API only sees the chosen one.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterRequest {
    first_name: String,
    last_name: String,
    email: String,
    password: String,
}

pub async fn register(
    req: HttpRequest,
    pool: web::Data<PgPool>,
    sessions: web::Data<SessionConfig>,
    body: web::Json<RegisterRequest>,
) -> Result<HttpResponse, AppError> {
    let body = body.into_inner();
    let first_name = clean_name("first name", &body.first_name)?;
    let last_name = clean_name("last name", &body.last_name)?;
    let email = normalize_email(&body.email)?;
    check_password_policy(&body.password, &email)?;

    let password = body.password;
    let hash = web::block(move || hash_password(&password))
        .await
        .map_err(blocking_failed)??;

    let user_id: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO users (id, email, first_name, last_name, password_hash)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (email) WHERE password_hash IS NOT NULL DO NOTHING
         RETURNING id",
    )
    .bind(Uuid::new_v4())
    .bind(&email)
    .bind(&first_name)
    .bind(&last_name)
    .bind(&hash)
    .fetch_optional(pool.get_ref())
    .await?;
    let Some(user_id) = user_id else {
        return Err(AppError::Conflict(
            "an account with this email already exists",
        ));
    };
    tracing::info!(%user_id, "account registered");

    let token = super::start_session(&req, &pool, &sessions, user_id).await?;
    let mut resp = HttpResponse::build(StatusCode::CREATED);
    super::session_cookie(&token, &sessions).apply(&mut resp);
    Ok(resp.json(json!({ "email": email })))
}

/// `POST /api/auth/password-login`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordLoginRequest {
    email: String,
    password: String,
}

pub async fn login(
    req: HttpRequest,
    pool: web::Data<PgPool>,
    sessions: web::Data<SessionConfig>,
    accounts: Option<web::Data<AccountLimiter>>,
    body: web::Json<PasswordLoginRequest>,
) -> Result<HttpResponse, AppError> {
    // Fail closed: no limiter means a wiring bug, not unlimited guessing.
    let accounts = accounts
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("account limiter not configured")))?;
    let body = body.into_inner();
    let email = body.email.trim().to_lowercase();
    // Bounds the hashing work an attacker can ask for.
    if email.len() > MAX_EMAIL_LEN || body.password.chars().count() > MAX_PASSWORD_CHARS {
        return Err(AppError::InvalidCredentials);
    }
    if !accounts.allow(&email) {
        tracing::warn!("sign-in attempts for one account throttled");
        return Err(AppError::TooManyRequests);
    }

    let row: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT id, password_hash FROM users WHERE email = $1 AND password_hash IS NOT NULL",
    )
    .bind(&email)
    .fetch_optional(pool.get_ref())
    .await?;

    let password = body.password;
    let user_id = web::block(move || -> Result<Option<Uuid>, AppError> {
        match row {
            Some((id, stored)) => Ok(verify_password(&password, &stored).then_some(id)),
            None => {
                verify_password(&password, dummy_hash()?);
                Ok(None)
            }
        }
    })
    .await
    .map_err(blocking_failed)??;
    let Some(user_id) = user_id else {
        tracing::info!("email sign-in failed");
        return Err(AppError::InvalidCredentials);
    };

    sqlx::query("UPDATE users SET last_login_at = now() WHERE id = $1")
        .bind(user_id)
        .execute(pool.get_ref())
        .await?;
    let token = super::start_session(&req, &pool, &sessions, user_id).await?;
    let mut resp = HttpResponse::Ok();
    super::session_cookie(&token, &sessions).apply(&mut resp);
    Ok(resp.json(json!({ "email": email })))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const PASSPHRASE: &str = "correct horse battery staple";

    #[test]
    fn hashes_are_salted_argon2id_and_verify() {
        let a = hash_password(PASSPHRASE).unwrap();
        let b = hash_password(PASSPHRASE).unwrap();
        assert!(a.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "{a}");
        assert_ne!(a, b, "same password must hash differently (salt)");
        assert!(!a.contains(PASSPHRASE));
        assert!(verify_password(PASSPHRASE, &a));
        assert!(!verify_password("correct horse battery stapler", &a));
        assert!(!verify_password(PASSPHRASE, "not a phc string"));
    }

    #[test]
    fn password_policy_is_length_based() {
        let email = "ada@example.com";
        assert!(check_password_policy(PASSPHRASE, email).is_ok());
        assert!(check_password_policy(&"a".repeat(12), email).is_ok());
        assert!(check_password_policy(&"é".repeat(128), email).is_ok());
        assert!(check_password_policy(&"a".repeat(11), email).is_err());
        assert!(check_password_policy(&"a".repeat(129), email).is_err());
        assert!(check_password_policy(&" ".repeat(20), email).is_err());
        assert!(check_password_policy("ADA@example.com", email).is_err());
    }

    #[test]
    fn emails_are_normalized_and_shape_checked() {
        assert_eq!(
            normalize_email("  Ada.Lovelace@Example.COM ").unwrap(),
            "ada.lovelace@example.com"
        );
        for bad in [
            "",
            "ada",
            "ada@",
            "@example.com",
            "ada@example",
            "ada@@example.com",
            "ada@.example.com",
            "ada@example..com",
            "a da@example.com",
            "<ada>@example.com",
            "ada@example.com\n",
        ] {
            let bad = bad.replace('\n', "\u{0}");
            assert!(normalize_email(&bad).is_err(), "{bad:?} accepted");
        }
        let long = format!("{}@example.com", "a".repeat(65));
        assert!(normalize_email(&long).is_err());
    }

    #[test]
    fn names_are_trimmed_and_bounded() {
        assert_eq!(clean_name("first name", "  Ada ").unwrap(), "Ada");
        assert!(clean_name("first name", "   ").is_err());
        assert!(clean_name("first name", &"x".repeat(101)).is_err());
        assert!(clean_name("first name", "Ada\u{7}").is_err());
    }

    #[test]
    fn account_limiter_is_per_account() {
        let limiter = AccountLimiter::with(Duration::from_secs(3600), 2);
        assert!(limiter.allow("a@example.com"));
        assert!(limiter.allow("a@example.com"));
        assert!(!limiter.allow("a@example.com"));
        assert!(limiter.allow("b@example.com"));
    }
}
