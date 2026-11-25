//! Opaque, server-side sessions (CASA 2.2.1, 2.2.3, 2.3.3, 2.3.4).
//!
//! The browser holds a random 256-bit token; the database holds only its
//! SHA-256. A session ends on logout, after `idle_secs` without use, or
//! `absolute_secs` after sign-in, whichever comes first. Expiry is checked by
//! the database clock on every request.

use sqlx::PgPool;
use uuid::Uuid;

use super::token::{digest, random_token};
use crate::error::AppError;

/// The signed-in user for this request. Only `require_session` creates it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthUser {
    pub user_id: Uuid,
}

/// Starts a session and returns the token to hand to the browser.
pub async fn create(pool: &PgPool, user_id: Uuid, absolute_secs: u32) -> Result<String, AppError> {
    let token = random_token()?;
    sqlx::query(
        "INSERT INTO sessions (token_hash, user_id, expires_at)
         VALUES ($1, $2, now() + make_interval(secs => $3))",
    )
    .bind(digest(&token))
    .bind(user_id)
    .bind(f64::from(absolute_secs))
    .execute(pool)
    .await?;
    Ok(token)
}

/// Looks up a live session and slides its idle window forward. `None` means
/// unknown, expired or idle too long: all are treated as signed out.
pub async fn resolve(
    pool: &PgPool,
    token: &str,
    idle_secs: u32,
) -> Result<Option<AuthUser>, AppError> {
    let user_id: Option<Uuid> = sqlx::query_scalar(
        "UPDATE sessions SET last_seen_at = now()
         WHERE token_hash = $1
           AND expires_at > now()
           AND last_seen_at > now() - make_interval(secs => $2)
         RETURNING user_id",
    )
    .bind(digest(token))
    .bind(f64::from(idle_secs))
    .fetch_optional(pool)
    .await?;
    Ok(user_id.map(|user_id| AuthUser { user_id }))
}

/// Like `resolve`, but *without* sliding the idle window, for requests the
/// page makes by itself (opening the live-update stream): they must not
/// count as the user being active (CASA 2.2.x).
pub async fn peek(
    pool: &PgPool,
    token: &str,
    idle_secs: u32,
) -> Result<Option<AuthUser>, AppError> {
    let user_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT user_id FROM sessions
          WHERE token_hash = $1
            AND expires_at > now()
            AND last_seen_at > now() - make_interval(secs => $2)",
    )
    .bind(digest(token))
    .bind(f64::from(idle_secs))
    .fetch_optional(pool)
    .await?;
    Ok(user_id.map(|user_id| AuthUser { user_id }))
}

/// The stored form of a session token: what `is_live` takes, so a
/// long-running task needn't keep the token itself.
pub fn token_hash(token: &str) -> Vec<u8> {
    digest(token)
}

/// Whether the session with this token hash is still live, *without*
/// sliding its idle window: a page left open doesn't keep a session alive
/// by itself (an open event stream checks this).
pub async fn is_live(pool: &PgPool, token_hash: &[u8], idle_secs: u32) -> Result<bool, AppError> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM sessions
          WHERE token_hash = $1
            AND expires_at > now()
            AND last_seen_at > now() - make_interval(secs => $2))",
    )
    .bind(token_hash)
    .bind(f64::from(idle_secs))
    .fetch_one(pool)
    .await?)
}

/// Ends a session (logout). Unknown tokens are ignored.
pub async fn revoke(pool: &PgPool, token: &str) -> Result<(), AppError> {
    sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
        .bind(digest(token))
        .execute(pool)
        .await?;
    Ok(())
}

/// Deletes dead sessions and abandoned sign-in attempts. Expired rows are
/// already rejected by `resolve`; this only keeps the tables small.
pub async fn purge_expired(pool: &PgPool, idle_secs: u32) -> Result<(), sqlx::Error> {
    sqlx::query(
        "DELETE FROM sessions
         WHERE expires_at <= now() OR last_seen_at <= now() - make_interval(secs => $1)",
    )
    .bind(f64::from(idle_secs))
    .execute(pool)
    .await?;
    sqlx::query("DELETE FROM oauth_logins WHERE expires_at <= now()")
        .execute(pool)
        .await?;
    Ok(())
}
