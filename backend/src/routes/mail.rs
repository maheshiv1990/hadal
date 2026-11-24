//! `/api/mail`: linked Gmail mailboxes and imported messages. Mounted behind
//! `require_session`; every handler acts only on the caller's own rows
//! (CASA 3.1.1, 3.1.4). Someone else's mailbox or message is a 404, exactly
//! like a missing one. Linking itself starts at `/api/auth/gmail/connect`.

use actix_web::http::header::{
    Charset, ContentDisposition, DispositionParam, DispositionType, ExtendedValue,
};
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
pub async fn accounts(
    user: AuthUser,
    pool: web::Data<PgPool>,
    cipher: web::Data<DataCipher>,
) -> Result<HttpResponse, AppError> {
    Ok(HttpResponse::Ok().json(mail::list_accounts(&pool, &cipher, user.user_id).await?))
}

#[delete("/accounts/{id}")]
pub async fn disconnect(
    user: AuthUser,
    pool: web::Data<PgPool>,
    google: web::Data<GoogleClient>,
    cipher: web::Data<DataCipher>,
    id: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    let grant = match mail::delete_account(&pool, &cipher, user.user_id, id.into_inner()).await? {
        mail::Unlinked::Removed(grant) => grant,
        mail::Unlinked::SignInAccount => {
            return Err(AppError::Conflict(
                "This is the account you sign in with, so it can't be disconnected.",
            ));
        }
        mail::Unlinked::NotFound => return Err(AppError::NotFound),
    };
    // Best effort: the mailbox and its mail are already deleted here.
    if let Some(grant) = grant
        && let Err(e) = google.revoke(&grant).await
    {
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

/// `?account=<mailbox id>&label=<ALL, a system folder or a user label ID>`,
/// both optional.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessagesQuery {
    account: Option<Uuid>,
    label: Option<String>,
}

#[get("/messages")]
pub async fn messages(
    user: AuthUser,
    pool: web::Data<PgPool>,
    cipher: web::Data<DataCipher>,
    query: web::Query<MessagesQuery>,
) -> Result<HttpResponse, AppError> {
    let MessagesQuery { account, label } = query.into_inner();
    let filter = match label {
        None => None,
        Some(raw) => Some(
            mail::LabelFilter::parse(&raw)
                .ok_or_else(|| AppError::BadRequest("invalid query string".into()))?,
        ),
    };
    Ok(HttpResponse::Ok()
        .json(mail::list_messages(&pool, &cipher, user.user_id, account, filter).await?))
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

/// Downloads attachment `index` of one of the caller's messages. Mounted at
/// `/api/mail/messages/{id}/attachments` (its own scope, for the tighter rate
/// limit: each download calls Google).
///
/// The file is always sent as `application/octet-stream` with
/// `Content-Disposition: attachment`, whatever type the email claims, and the
/// API's `nosniff` and `default-src 'none'` CSP still apply. So a file from a
/// stranger's email is saved, never rendered on our origin (CASA 5.1.7).
#[get("/{index}")]
pub async fn attachment(
    user: AuthUser,
    pool: web::Data<PgPool>,
    google: web::Data<GoogleClient>,
    cipher: web::Data<DataCipher>,
    path: web::Path<(Uuid, usize)>,
) -> Result<HttpResponse, AppError> {
    let (message_id, index) = path.into_inner();
    let Some(file) =
        mail::download_attachment(&pool, &google, &cipher, user.user_id, message_id, index).await?
    else {
        return Err(AppError::NotFound);
    };
    Ok(HttpResponse::Ok()
        .content_type("application/octet-stream")
        .insert_header(download_disposition(&file.filename))
        .body(file.bytes))
}

/// `attachment; filename="<ASCII fallback>"; filename*=UTF-8''<exact name>`.
/// The exact name is percent-encoded by actix, and the fallback keeps only
/// characters that need no quoting, so the header can't be broken out of.
fn download_disposition(name: &str) -> ContentDisposition {
    let fallback: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || " .-_()".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect();
    ContentDisposition {
        disposition: DispositionType::Attachment,
        parameters: vec![
            DispositionParam::Filename(fallback),
            DispositionParam::FilenameExt(ExtendedValue {
                charset: Charset::Ext("UTF-8".to_owned()),
                language_tag: None,
                value: name.as_bytes().to_vec(),
            }),
        ],
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use actix_web::http::header::TryIntoHeaderValue;

    #[test]
    fn download_names_cannot_break_the_header() {
        let header = |name: &str| {
            download_disposition(name)
                .try_into_value()
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned()
        };
        assert_eq!(
            header("Q3 report (final).pdf"),
            "attachment; filename=\"Q3 report (final).pdf\"; \
             filename*=UTF-8''Q3%20report%20%28final%29.pdf"
        );
        // Quotes, semicolons and spaces are encoded, so the name can't add or
        // end a parameter. (actix leaves '=' as is, which is harmless here.)
        let tricky = header("a\"; filename=evil.html; x=\"ü.txt");
        assert!(tricky.starts_with("attachment; filename=\"a__ filename_evil.html_ x___.txt\"; "));
        assert!(
            tricky.ends_with("filename*=UTF-8''a%22%3B%20filename=evil.html%3B%20x=%22%C3%BC.txt"),
            "{tricky}"
        );
    }
}
