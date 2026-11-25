//! `POST /api/gmail/push`: Cloud Pub/Sub delivers Gmail's "mailbox changed"
//! notifications here.
//!
//! The one API route without a session (besides health and sign-in): Google
//! calls it, not a browser. What lets a request in instead is the token in
//! `Authorization: Bearer`, signed by Google for our subscription's audience
//! and service account (`GoogleClient::verify_push_token`). Anything else is a
//! 401. Even a genuine notification only names a mailbox: nothing from it
//! picks an owner or reaches Gmail, and the sync it starts reads from Gmail
//! with our own stored grant (CASA 3.1.1, 3.1.4).

use actix_web::{HttpRequest, HttpResponse, post, web};
use base64::Engine;
use base64::alphabet::STANDARD;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use serde_json::Value;
use sqlx::PgPool;

use crate::auth::google::{GoogleClient, PushExpectation, PushRejected, valid_history_id};
use crate::error::AppError;
use crate::mail;
use crate::push::Push;

/// Pub/Sub sends message data as base64, padded or not.
const PUBSUB_BASE64: GeneralPurpose = GeneralPurpose::new(
    &STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);
/// Longest email address accepted (users.email allows 320).
const MAX_EMAIL_CHARS: usize = 320;

/// Mounted at `/api/gmail` (its own scope, so the rest of the API stays
/// behind `require_session`).
#[post("/push")]
pub async fn push(
    req: HttpRequest,
    push: Option<web::Data<Push>>,
    google: web::Data<GoogleClient>,
    pool: web::Data<PgPool>,
    // Raw bytes: nothing in the body is parsed until the token checks out.
    body: web::Bytes,
) -> Result<HttpResponse, AppError> {
    // Push not configured: the route doesn't exist.
    let Some(push) = push else {
        return Err(AppError::NotFound);
    };
    let token = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(AppError::Unauthorized)?;
    let expect = PushExpectation {
        audience: &push.config.audience,
        service_account: &push.config.service_account,
    };
    if let Err(e) = google.verify_push_token(token, &expect).await {
        tracing::warn!(reason = %e, "push request refused");
        return Err(match e {
            // Not the sender's fault: Pub/Sub retries it later.
            PushRejected::KeysUnavailable(_) => {
                AppError::Upstream("could not check the request right now")
            }
            _ => AppError::Unauthorized,
        });
    }

    // From here on it is Google. Anything we can't use is acknowledged
    // (2xx), so Pub/Sub doesn't redeliver it for days.
    let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let Some(email) = notified_mailbox(&body) else {
        tracing::warn!("push notification without a usable mailbox; acknowledged");
        return Ok(HttpResponse::NoContent().finish());
    };
    for mailbox in mail::watched_mailboxes(&pool, &email).await? {
        push.enqueue(mailbox);
    }
    Ok(HttpResponse::NoContent().finish())
}

/// The Gmail address a Pub/Sub push names: `message.data` is base64 JSON
/// `{"emailAddress": ..., "historyId": ...}`. The history ID isn't used:
/// each sync reads from the point it stored itself.
fn notified_mailbox(body: &Value) -> Option<String> {
    let data = body.get("message")?.get("data")?.as_str()?;
    let decoded = PUBSUB_BASE64.decode(data.trim()).ok()?;
    let note: Value = serde_json::from_slice(&decoded).ok()?;
    note.get("historyId")
        .and_then(|h| match h {
            Value::String(s) => Some(valid_history_id(s)),
            Value::Number(n) => Some(n.is_u64()),
            _ => None,
        })
        .filter(|ok| *ok)?;
    let email = note.get("emailAddress")?.as_str()?;
    (email.contains('@') && email.chars().count() <= MAX_EMAIL_CHARS).then(|| email.to_owned())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    fn body(note: &Value) -> Value {
        let data = base64::engine::general_purpose::STANDARD.encode(note.to_string());
        json!({
            "message": {"data": data, "messageId": "1", "publishTime": "2026-11-24T10:00:00Z"},
            "subscription": "projects/hadal-test/subscriptions/gmail-push",
        })
    }

    #[test]
    fn notifications_name_a_mailbox_and_nothing_else_is_trusted() {
        let good = json!({"emailAddress": "ada@example.com", "historyId": 9876});
        assert_eq!(
            notified_mailbox(&body(&good)).as_deref(),
            Some("ada@example.com")
        );
        let as_string = json!({"emailAddress": "ada@example.com", "historyId": "9876"});
        assert!(notified_mailbox(&body(&as_string)).is_some());
        for bad in [
            json!({"emailAddress": "ada@example.com"}),
            json!({"emailAddress": "ada@example.com", "historyId": "-1"}),
            json!({"emailAddress": "not-an-address", "historyId": 1}),
            json!({"emailAddress": format!("{}@x.com", "a".repeat(320)), "historyId": 1}),
            json!({"historyId": 1}),
        ] {
            assert!(notified_mailbox(&body(&bad)).is_none(), "accepted {bad}");
        }
        assert!(notified_mailbox(&json!({"message": {"data": "%%%"}})).is_none());
        assert!(notified_mailbox(&json!({})).is_none());
    }
}
