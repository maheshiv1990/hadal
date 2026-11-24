//! `/api/mail`: linked Gmail mailboxes and imported messages. Mounted behind
//! `require_session`; every handler acts only on the caller's own rows
//! (CASA 3.1.1, 3.1.4). Someone else's mailbox or message is a 404, exactly
//! like a missing one. Linking itself starts at `/api/auth/gmail/connect`.

use actix_web::{HttpResponse, delete, get, post, web};
use serde::Deserialize;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::auth::google::GoogleClient;
use crate::crypto::DataCipher;
use crate::error::AppError;
use crate::mail::{self, ImportOutcome};

#[get("/accounts")]
pub async fn accounts(user: AuthUser, pool: web::Data<PgPool>) -> Result<HttpResponse, AppError> {
    Ok(HttpResponse::Ok().json(mail::list_accounts(&pool, user.user_id).await?))
}

#[delete("/accounts/{id}")]
pub async fn disconnect(
    user: AuthUser,
    pool: web::Data<PgPool>,
    google: web::Data<GoogleClient>,
    cipher: web::Data<DataCipher>,
    id: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    let Some(grant) = mail::delete_account(&pool, &cipher, user.user_id, id.into_inner()).await?
    else {
        return Err(AppError::NotFound);
    };
    // Best effort: the mailbox and its mail are already deleted here.
    if let Err(e) = google.revoke(&grant).await {
        tracing::warn!(error = %e, "could not revoke Google access for an unlinked mailbox");
    }
    Ok(HttpResponse::NoContent().finish())
}

/// Import takes a JSON body so a cross-site form can't start one (CASA 3.1.5).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportRequest {}

/// Mounted at `/api/mail/import` (its own scope, for the tighter rate limit).
#[post("")]
pub async fn import(
    user: AuthUser,
    pool: web::Data<PgPool>,
    google: web::Data<GoogleClient>,
    cipher: web::Data<DataCipher>,
    _body: web::Json<ImportRequest>,
) -> Result<HttpResponse, AppError> {
    match mail::import_all(
        &pool,
        google.into_inner(),
        cipher.into_inner(),
        user.user_id,
    )
    .await?
    {
        ImportOutcome::Done(results) => {
            let imported: u32 = results.iter().map(|a| a.imported).sum();
            Ok(HttpResponse::Ok().json(json!({ "imported": imported, "accounts": results })))
        }
        ImportOutcome::Busy => Err(AppError::Conflict("an import is already running")),
    }
}

#[get("/messages")]
pub async fn messages(
    user: AuthUser,
    pool: web::Data<PgPool>,
    cipher: web::Data<DataCipher>,
) -> Result<HttpResponse, AppError> {
    Ok(HttpResponse::Ok().json(mail::list_messages(&pool, &cipher, user.user_id).await?))
}

#[get("/messages/{id}")]
pub async fn message(
    user: AuthUser,
    pool: web::Data<PgPool>,
    cipher: web::Data<DataCipher>,
    id: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    mail::get_message(&pool, &cipher, user.user_id, id.into_inner())
        .await?
        .map(|m| HttpResponse::Ok().json(m))
        .ok_or(AppError::NotFound)
}
