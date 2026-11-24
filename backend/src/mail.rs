//! Linked Gmail mailboxes and imported mail.
//!
//! - Every query is scoped by `owner_id` from the session (CASA 3.1.4,
//!   lint:notes-owner-scope); messages also carry a foreign key to their
//!   mailbox *and* its owner, so a row can't point at someone else's mailbox.
//! - Refresh tokens and message content are encrypted with `DataCipher`, bound
//!   to their row (CASA 6.7.1). Access tokens live only in memory.
//! - Bodies are reduced to plain text here and shown as text by the frontend,
//!   so mail HTML is never rendered (CASA 5.1.7).

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use base64::Engine;
use base64::alphabet::URL_SAFE;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use time::OffsetDateTime;
use tokio::task::JoinSet;
use uuid::Uuid;

use crate::auth::google::{GoogleApiError, GoogleClient, Identity, valid_gmail_id};
use crate::config::Secret;
use crate::crypto::DataCipher;
use crate::error::AppError;

/// Most mailboxes one user may link.
pub const MAX_MAILBOXES: i64 = 10;
/// Newest messages fetched per mailbox on each import.
pub const IMPORT_PER_MAILBOX: u32 = 100;
/// Parallel message fetches per mailbox.
const FETCH_CONCURRENCY: usize = 8;
/// An import must answer before nginx gives up on the request
/// (`proxy_read_timeout 30s`). What was stored by then is kept.
const IMPORT_BUDGET: Duration = Duration::from_secs(24);
/// A claim on a mailbox older than this is from a crashed import.
const STALE_CLAIM_SECS: f64 = 300.0;
const MAX_BODY_CHARS: usize = 200_000;
const MAX_SUBJECT_CHARS: usize = 1_000;
const MAX_ADDRESS_CHARS: usize = 2_000;
const MAX_SNIPPET_CHARS: usize = 500;
/// Most messages returned by one list call.
pub const LIST_LIMIT: i64 = 200;

/// Gmail encodes bodies as base64url, sometimes with padding.
const GMAIL_BASE64: GeneralPurpose = GeneralPurpose::new(
    &URL_SAFE,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

// Associated data binds each ciphertext to the row it was written for.
fn token_aad(owner: Uuid, google_sub: &str) -> Vec<u8> {
    let mut aad = b"mail_accounts.refresh_token\0".to_vec();
    aad.extend_from_slice(owner.as_bytes());
    aad.extend_from_slice(google_sub.as_bytes());
    aad
}

fn message_aad(field: &str, owner: Uuid, message_id: Uuid) -> Vec<u8> {
    let mut aad = b"mail_messages.".to_vec();
    aad.extend_from_slice(field.as_bytes());
    aad.push(0);
    aad.extend_from_slice(owner.as_bytes());
    aad.extend_from_slice(message_id.as_bytes());
    aad
}

// ---- linking --------------------------------------------------------------

pub enum Stored {
    Linked,
    LimitReached,
}

/// Stores (or, for the same Google account, updates) a linked mailbox.
pub async fn store_account(
    pool: &PgPool,
    cipher: &DataCipher,
    owner: Uuid,
    identity: &Identity,
    refresh: &Secret,
) -> Result<Stored, AppError> {
    let others: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mail_accounts WHERE owner_id = $1 AND google_sub <> $2",
    )
    .bind(owner)
    .bind(&identity.sub)
    .fetch_one(pool)
    .await?;
    if others >= MAX_MAILBOXES {
        return Ok(Stored::LimitReached);
    }
    let sealed = cipher.encrypt(
        refresh.expose().as_bytes(),
        &token_aad(owner, &identity.sub),
    )?;
    sqlx::query(
        "INSERT INTO mail_accounts (id, owner_id, google_sub, email, refresh_token_enc)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (owner_id, google_sub) DO UPDATE SET
             email = EXCLUDED.email,
             refresh_token_enc = EXCLUDED.refresh_token_enc",
    )
    .bind(Uuid::new_v4())
    .bind(owner)
    .bind(&identity.sub)
    .bind(&identity.email)
    .bind(sealed)
    .execute(pool)
    .await?;
    Ok(Stored::Linked)
}

#[derive(Serialize, sqlx::FromRow)]
pub struct Account {
    id: Uuid,
    email: String,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    last_import_at: Option<OffsetDateTime>,
    message_count: i64,
}

pub async fn list_accounts(pool: &PgPool, owner: Uuid) -> Result<Vec<Account>, AppError> {
    Ok(sqlx::query_as::<_, Account>(
        "SELECT a.id, a.email, a.created_at, a.last_import_at,
                (SELECT count(*) FROM mail_messages m
                  WHERE m.owner_id = $1 AND m.account_id = a.id) AS message_count
           FROM mail_accounts a
          WHERE a.owner_id = $1
          ORDER BY a.created_at",
    )
    .bind(owner)
    .fetch_all(pool)
    .await?)
}

/// Unlinks a mailbox and deletes its messages. Returns its refresh token so
/// the caller can revoke it at Google. `None` if it isn't the caller's.
pub async fn delete_account(
    pool: &PgPool,
    cipher: &DataCipher,
    owner: Uuid,
    id: Uuid,
) -> Result<Option<Secret>, AppError> {
    let row: Option<(String, Vec<u8>)> = sqlx::query_as(
        "DELETE FROM mail_accounts WHERE id = $1 AND owner_id = $2
         RETURNING google_sub, refresh_token_enc",
    )
    .bind(id)
    .bind(owner)
    .fetch_optional(pool)
    .await?;
    let Some((sub, sealed)) = row else {
        return Ok(None);
    };
    // The mailbox is already gone; a token that won't decrypt just can't be
    // revoked from here.
    Ok(open_token(cipher, owner, &sub, &sealed).ok())
}

fn open_token(
    cipher: &DataCipher,
    owner: Uuid,
    sub: &str,
    sealed: &[u8],
) -> Result<Secret, AppError> {
    let plain = cipher.decrypt(sealed, &token_aad(owner, sub))?;
    String::from_utf8(plain)
        .map(Secret::new)
        .map_err(|_| AppError::Internal(anyhow::anyhow!("stored grant is not UTF-8")))
}

// ---- reading imported mail ------------------------------------------------

/// Sender, recipients, subject and Gmail's snippet, stored encrypted as JSON.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Summary {
    pub from: String,
    pub to: String,
    pub subject: String,
    pub snippet: String,
}

#[derive(Serialize)]
pub struct MessageItem {
    id: Uuid,
    account_id: Uuid,
    account_email: String,
    #[serde(with = "time::serde::rfc3339")]
    received_at: OffsetDateTime,
    #[serde(flatten)]
    summary: Summary,
}

#[derive(Serialize)]
pub struct MessageDetail {
    #[serde(flatten)]
    item: MessageItem,
    /// Plain text only; never HTML.
    body: String,
}

fn open_summary(
    cipher: &DataCipher,
    owner: Uuid,
    id: Uuid,
    sealed: &[u8],
) -> Result<Summary, AppError> {
    let plain = cipher.decrypt(sealed, &message_aad("summary", owner, id))?;
    serde_json::from_slice(&plain)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("stored summary is invalid: {e}")))
}

type ItemRow = (Uuid, Uuid, String, OffsetDateTime, Vec<u8>);
type DetailRow = (Uuid, String, OffsetDateTime, Vec<u8>, Vec<u8>);

/// Newest imported messages across all of the user's mailboxes.
pub async fn list_messages(
    pool: &PgPool,
    cipher: &DataCipher,
    owner: Uuid,
) -> Result<Vec<MessageItem>, AppError> {
    let rows: Vec<ItemRow> = sqlx::query_as(
        "SELECT m.id, m.account_id, a.email, m.received_at, m.summary_enc
           FROM mail_messages m
           JOIN mail_accounts a ON a.id = m.account_id AND a.owner_id = m.owner_id
          WHERE m.owner_id = $1
          ORDER BY m.received_at DESC
          LIMIT $2",
    )
    .bind(owner)
    .bind(LIST_LIMIT)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|(id, account_id, account_email, received_at, sealed)| {
            Ok(MessageItem {
                id,
                account_id,
                account_email,
                received_at,
                summary: open_summary(cipher, owner, id, &sealed)?,
            })
        })
        .collect()
}

/// One message with its body. `None` if it isn't the caller's.
pub async fn get_message(
    pool: &PgPool,
    cipher: &DataCipher,
    owner: Uuid,
    id: Uuid,
) -> Result<Option<MessageDetail>, AppError> {
    let row: Option<DetailRow> = sqlx::query_as(
        "SELECT m.account_id, a.email, m.received_at, m.summary_enc, m.body_enc
           FROM mail_messages m
           JOIN mail_accounts a ON a.id = m.account_id AND a.owner_id = m.owner_id
          WHERE m.id = $1 AND m.owner_id = $2",
    )
    .bind(id)
    .bind(owner)
    .fetch_optional(pool)
    .await?;
    let Some((account_id, account_email, received_at, summary, body)) = row else {
        return Ok(None);
    };
    let body = cipher.decrypt(&body, &message_aad("body", owner, id))?;
    Ok(Some(MessageDetail {
        item: MessageItem {
            id,
            account_id,
            account_email,
            received_at,
            summary: open_summary(cipher, owner, id, &summary)?,
        },
        body: String::from_utf8_lossy(&body).into_owned(),
    }))
}

// ---- importing --------------------------------------------------------------

/// Outcome for one mailbox. `error` is a fixed, user-facing message; the
/// detail is logged server-side only (CASA 6.2.1).
#[derive(Serialize, Debug)]
pub struct AccountImport {
    pub id: Uuid,
    pub email: String,
    pub imported: u32,
    pub skipped: u32,
    pub error: Option<&'static str>,
}

pub enum ImportOutcome {
    Done(Vec<AccountImport>),
    /// Every mailbox is already being imported by another request.
    Busy,
}

struct Claimed {
    id: Uuid,
    google_sub: String,
    email: String,
    sealed_token: Vec<u8>,
}

#[derive(Debug)]
enum ImportFailure {
    Google(GoogleApiError),
    App(AppError),
}

impl ImportFailure {
    fn user_message(&self) -> &'static str {
        match self {
            ImportFailure::Google(GoogleApiError::Revoked) => {
                "Google access was revoked or expired. Reconnect this mailbox."
            }
            ImportFailure::Google(_) => "Could not reach Gmail. Try again.",
            ImportFailure::App(_) => "Import failed. Try again.",
        }
    }
}

impl std::fmt::Display for ImportFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImportFailure::Google(e) => write!(f, "{e}"),
            // Server-side log only; AppError's Display is the generic message.
            ImportFailure::App(e) => write!(f, "{e:?}"),
        }
    }
}

impl From<GoogleApiError> for ImportFailure {
    fn from(e: GoogleApiError) -> Self {
        ImportFailure::Google(e)
    }
}

impl From<AppError> for ImportFailure {
    fn from(e: AppError) -> Self {
        ImportFailure::App(e)
    }
}

impl From<sqlx::Error> for ImportFailure {
    fn from(e: sqlx::Error) -> Self {
        ImportFailure::App(e.into())
    }
}

/// Imports the newest `IMPORT_PER_MAILBOX` messages from every mailbox the
/// user linked, all mailboxes at once. Messages already imported are not
/// fetched again.
pub async fn import_all(
    pool: &PgPool,
    google: Arc<GoogleClient>,
    cipher: Arc<DataCipher>,
    owner: Uuid,
) -> Result<ImportOutcome, AppError> {
    // Claim the mailboxes so a second click can't import them twice at once.
    let claimed: Vec<(Uuid, String, String, Vec<u8>)> = sqlx::query_as(
        "UPDATE mail_accounts SET import_started_at = now()
          WHERE owner_id = $1
            AND (import_started_at IS NULL
                 OR import_started_at < now() - make_interval(secs => $2))
          RETURNING id, google_sub, email, refresh_token_enc",
    )
    .bind(owner)
    .bind(STALE_CLAIM_SECS)
    .fetch_all(pool)
    .await?;
    if claimed.is_empty() {
        let linked: i64 =
            sqlx::query_scalar("SELECT count(*) FROM mail_accounts WHERE owner_id = $1")
                .bind(owner)
                .fetch_one(pool)
                .await?;
        return Ok(if linked > 0 {
            ImportOutcome::Busy
        } else {
            ImportOutcome::Done(Vec::new())
        });
    }
    let ids: Vec<Uuid> = claimed.iter().map(|c| c.0).collect();

    let mut tasks = JoinSet::new();
    for (id, google_sub, email, sealed_token) in claimed {
        let account = Claimed {
            id,
            google_sub,
            email,
            sealed_token,
        };
        let (pool, google, cipher) = (pool.clone(), google.clone(), cipher.clone());
        tasks.spawn(async move {
            let imported = Arc::new(AtomicU32::new(0));
            let skipped = Arc::new(AtomicU32::new(0));
            let run = import_account(
                &pool,
                &google,
                &cipher,
                owner,
                &account,
                imported.clone(),
                skipped.clone(),
            );
            let error = match tokio::time::timeout(IMPORT_BUDGET, run).await {
                Ok(Ok(())) => None,
                Ok(Err(e)) => {
                    tracing::warn!(account = %account.id, error = %e, "mailbox import failed");
                    Some(e.user_message())
                }
                Err(_) => Some("Import ran out of time. Run it again to continue."),
            };
            AccountImport {
                id: account.id,
                email: account.email,
                imported: imported.load(Ordering::Relaxed),
                skipped: skipped.load(Ordering::Relaxed),
                error,
            }
        });
    }
    let mut results = Vec::with_capacity(ids.len());
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok(result) => results.push(result),
            Err(e) => tracing::error!(error = %e, "mailbox import task failed"),
        }
    }

    // Release every claim, including any whose task died.
    let finished: Vec<Uuid> = results
        .iter()
        .filter(|r| r.error.is_none())
        .map(|r| r.id)
        .collect();
    sqlx::query(
        "UPDATE mail_accounts SET
             import_started_at = NULL,
             last_import_at = CASE WHEN id = ANY($3) THEN now() ELSE last_import_at END
          WHERE owner_id = $1 AND id = ANY($2)",
    )
    .bind(owner)
    .bind(&ids)
    .bind(&finished)
    .execute(pool)
    .await?;

    results.sort_by(|a, b| a.email.cmp(&b.email));
    Ok(ImportOutcome::Done(results))
}

async fn import_account(
    pool: &PgPool,
    google: &Arc<GoogleClient>,
    cipher: &DataCipher,
    owner: Uuid,
    account: &Claimed,
    imported: Arc<AtomicU32>,
    skipped: Arc<AtomicU32>,
) -> Result<(), ImportFailure> {
    let refresh = open_token(cipher, owner, &account.google_sub, &account.sealed_token)?;
    let access = google.refresh_access_token(&refresh).await?;
    let ids = google.list_message_ids(&access, IMPORT_PER_MAILBOX).await?;

    let known: Vec<String> = sqlx::query_scalar(
        "SELECT gmail_id FROM mail_messages
          WHERE owner_id = $1 AND account_id = $2 AND gmail_id = ANY($3)",
    )
    .bind(owner)
    .bind(account.id)
    .bind(&ids)
    .fetch_all(pool)
    .await?;
    let mut pending = ids.into_iter().filter(|id| !known.contains(id));

    let mut fetches = JoinSet::new();
    loop {
        while fetches.len() < FETCH_CONCURRENCY {
            let Some(id) = pending.next() else { break };
            let (google, access) = (google.clone(), access.clone());
            fetches.spawn(async move { google.get_message(&access, &id).await });
        }
        let Some(joined) = fetches.join_next().await else {
            break;
        };
        let message = match joined {
            Ok(Ok(message)) => message,
            Ok(Err(GoogleApiError::Revoked)) => return Err(GoogleApiError::Revoked.into()),
            Ok(Err(e)) => {
                tracing::warn!(account = %account.id, error = %e, "message fetch failed");
                skipped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            Err(e) => {
                tracing::warn!(account = %account.id, error = %e, "message fetch task failed");
                skipped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
        };
        let Some(parsed) = parse_message(&message) else {
            skipped.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        if store_message(pool, cipher, owner, account.id, &parsed).await? {
            imported.fetch_add(1, Ordering::Relaxed);
        }
    }
    Ok(())
}

/// Returns false if the message was already stored (a concurrent import).
async fn store_message(
    pool: &PgPool,
    cipher: &DataCipher,
    owner: Uuid,
    account_id: Uuid,
    msg: &Parsed,
) -> Result<bool, AppError> {
    let id = Uuid::new_v4();
    let summary = serde_json::to_vec(&msg.summary)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("summary encoding failed: {e}")))?;
    let summary = cipher.encrypt(&summary, &message_aad("summary", owner, id))?;
    let body = cipher.encrypt(msg.body.as_bytes(), &message_aad("body", owner, id))?;
    let result = sqlx::query(
        "INSERT INTO mail_messages
             (id, owner_id, account_id, gmail_id, received_at, summary_enc, body_enc)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (account_id, gmail_id) DO NOTHING",
    )
    .bind(id)
    .bind(owner)
    .bind(account_id)
    .bind(&msg.gmail_id)
    .bind(msg.received_at)
    .bind(summary)
    .bind(body)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

// ---- parsing Gmail messages -------------------------------------------------

#[derive(Debug)]
pub struct Parsed {
    pub gmail_id: String,
    pub received_at: OffsetDateTime,
    pub summary: Summary,
    pub body: String,
}

/// Reads a `format=full` Gmail message. `None` if it is malformed.
pub fn parse_message(msg: &Value) -> Option<Parsed> {
    let gmail_id = msg.get("id")?.as_str().filter(|id| valid_gmail_id(id))?;
    let millis: i64 = msg.get("internalDate")?.as_str()?.parse().ok()?;
    let received_at =
        OffsetDateTime::from_unix_timestamp_nanos(i128::from(millis) * 1_000_000).ok()?;
    let payload = msg.get("payload")?;
    let header = |name: &str| -> String {
        payload
            .get("headers")
            .and_then(Value::as_array)
            .and_then(|hs| {
                hs.iter().find(|h| {
                    h.get("name")
                        .and_then(Value::as_str)
                        .is_some_and(|n| n.eq_ignore_ascii_case(name))
                })
            })
            .and_then(|h| h.get("value"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let summary = Summary {
        from: clean_line(&header("From"), MAX_ADDRESS_CHARS),
        to: clean_line(&header("To"), MAX_ADDRESS_CHARS),
        subject: clean_line(&header("Subject"), MAX_SUBJECT_CHARS),
        snippet: clean_line(
            &decode_entities(msg.get("snippet").and_then(Value::as_str).unwrap_or("")),
            MAX_SNIPPET_CHARS,
        ),
    };
    let body = if let Some(text) = part_text(payload, "text/plain", 0) {
        text.replace("\r\n", "\n")
    } else if let Some(html) = part_text(payload, "text/html", 0) {
        html_to_text(&html)
    } else {
        String::new()
    };
    Some(Parsed {
        gmail_id: gmail_id.to_owned(),
        received_at,
        summary,
        body: cap_body(body),
    })
}

/// Drops control characters, trims, and cuts to `max` characters.
fn clean_line(s: &str, max: usize) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .trim()
        .chars()
        .take(max)
        .collect()
}

fn cap_body(mut body: String) -> String {
    // Keep newlines and tabs; drop other control characters.
    body.retain(|c| c == '\n' || c == '\t' || !c.is_control());
    if body.chars().count() > MAX_BODY_CHARS {
        body = body.chars().take(MAX_BODY_CHARS).collect();
        body.push_str("\n\n[message truncated]");
    }
    body.trim().to_owned()
}

/// The decoded body of the first inline (non-attachment) part of type
/// `mime`, searching nested multipart parts.
fn part_text(part: &Value, mime: &str, depth: u8) -> Option<String> {
    if depth > 16 {
        return None;
    }
    let is_attachment = part
        .get("filename")
        .and_then(Value::as_str)
        .is_some_and(|f| !f.is_empty());
    let mime_matches = part
        .get("mimeType")
        .and_then(Value::as_str)
        .is_some_and(|m| m.eq_ignore_ascii_case(mime));
    if mime_matches
        && !is_attachment
        && let Some(data) = part
            .get("body")
            .and_then(|b| b.get("data"))
            .and_then(Value::as_str)
    {
        let bytes = GMAIL_BASE64.decode(data.trim()).ok()?;
        return Some(String::from_utf8_lossy(&bytes).into_owned());
    }
    part.get("parts")?
        .as_array()?
        .iter()
        .find_map(|p| part_text(p, mime, depth + 1))
}

/// Turns an HTML body into readable plain text. The result is always shown
/// as text, never parsed as HTML, so this only has to be readable, not a
/// security boundary.
pub fn html_to_text(html: &str) -> String {
    let lower = html.to_ascii_lowercase();
    let mut out = String::with_capacity(html.len() / 2);
    let mut i = 0;
    while i < html.len() {
        let Some(lt) = html[i..].find('<').map(|o| i + o) else {
            push_text(&mut out, &html[i..]);
            break;
        };
        push_text(&mut out, &html[i..lt]);
        if lower[lt..].starts_with("<!--") {
            i = lower[lt..].find("-->").map_or(html.len(), |o| lt + o + 3);
            continue;
        }
        let Some(gt) = html[lt..].find('>').map(|o| lt + o) else {
            break;
        };
        let tag = &lower[lt + 1..gt];
        let closing = tag.starts_with('/');
        let name: String = tag
            .trim_start_matches('/')
            .chars()
            .take_while(char::is_ascii_alphanumeric)
            .collect();
        i = gt + 1;
        if !closing && matches!(name.as_str(), "script" | "style" | "head" | "title") {
            // Skip the element's content up to its closing tag.
            let close = format!("</{name}");
            i = lower[i..].find(&close).map_or(html.len(), |o| i + o);
            continue;
        }
        match name.as_str() {
            "br" => out.push('\n'),
            // Block boundaries start a new line, without stacking blank ones.
            "p" | "div" | "tr" | "li" | "table" | "blockquote" | "hr" | "h1" | "h2" | "h3"
            | "h4" | "h5" | "h6"
                if !out.is_empty() && !out.ends_with('\n') =>
            {
                out.push('\n')
            }
            "td" | "th" => out.push(' '),
            _ => {}
        }
    }
    tidy_lines(&out)
}

/// Appends an HTML text node: entities decoded, whitespace collapsed.
fn push_text(out: &mut String, raw: &str) {
    let text = decode_entities(raw);
    let mut last_space = out.ends_with([' ', '\n']) || out.is_empty();
    for c in text.chars() {
        if c.is_whitespace() && c != '\u{a0}' {
            if !last_space {
                out.push(' ');
                last_space = true;
            }
        } else {
            out.push(if c == '\u{a0}' { ' ' } else { c });
            last_space = false;
        }
    }
}

/// Trims each line and keeps at most one blank line in a row.
fn tidy_lines(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut blank = 0;
    for line in s.lines().map(str::trim) {
        if line.is_empty() {
            blank += 1;
            if blank > 1 {
                continue;
            }
        } else {
            blank = 0;
        }
        out.push_str(line);
        out.push('\n');
    }
    out.trim().to_owned()
}

/// Decodes the HTML entities that show up in mail and Gmail snippets.
fn decode_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after = &rest[amp + 1..];
        let decoded = after.find(';').filter(|&end| end <= 10).and_then(|end| {
            let name = &after[..end];
            let c = match name {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" | "#39" => Some('\''),
                "nbsp" => Some('\u{a0}'),
                _ => name
                    .strip_prefix("#x")
                    .or_else(|| name.strip_prefix("#X"))
                    .and_then(|hex| u32::from_str_radix(hex, 16).ok())
                    .or_else(|| name.strip_prefix('#').and_then(|d| d.parse().ok()))
                    .and_then(char::from_u32),
            }?;
            Some((c, end))
        });
        match decoded {
            Some((c, end)) => {
                out.push(c);
                rest = &after[end + 1..];
            }
            None => {
                out.push('&');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    pub(crate) fn b64(s: &str) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s)
    }

    /// A Gmail `format=full` message with a plain and an HTML alternative
    /// and an attachment.
    pub(crate) fn gmail_message(id: &str, subject: &str, text: &str) -> Value {
        json!({
            "id": id,
            "threadId": id,
            "internalDate": "1764000000000",
            "snippet": "Hi Ada &amp; team, it&#39;s ready",
            "payload": {
                "mimeType": "multipart/mixed",
                "headers": [
                    {"name": "From", "value": "Grace <grace@example.com>"},
                    {"name": "to", "value": "ada@example.com"},
                    {"name": "Subject", "value": subject},
                ],
                "parts": [
                    {"mimeType": "multipart/alternative", "parts": [
                        {"mimeType": "text/html", "filename": "",
                         "body": {"data": b64("<p>html version</p>")}},
                        {"mimeType": "text/plain", "filename": "",
                         "body": {"data": b64(text)}},
                    ]},
                    {"mimeType": "text/plain", "filename": "notes.txt",
                     "body": {"attachmentId": "att1", "size": 10}},
                ],
            },
        })
    }

    #[test]
    fn parses_headers_snippet_and_prefers_the_plain_body() {
        let msg = gmail_message("18c2f0a9", "Launch", "Line one\r\nLine two");
        let p = parse_message(&msg).unwrap();
        assert_eq!(p.gmail_id, "18c2f0a9");
        assert_eq!(p.received_at.unix_timestamp(), 1_764_000_000);
        assert_eq!(
            p.summary,
            Summary {
                from: "Grace <grace@example.com>".into(),
                to: "ada@example.com".into(),
                subject: "Launch".into(),
                snippet: "Hi Ada & team, it's ready".into(),
            }
        );
        assert_eq!(p.body, "Line one\nLine two");
    }

    #[test]
    fn html_only_bodies_become_text_with_scripts_and_styles_dropped() {
        let html = "<html><head><title>t</title><style>p{color:red}</style></head>\
                    <body><p>Hello&nbsp;<b>there</b></p><script>alert(1)</script>\
                    <!-- <p>hidden</p> --><div>a &lt;tag&gt; &#x1F600;</div><br>bye</body></html>";
        let text = "Hello there\na <tag> \u{1F600}\n\nbye";
        assert_eq!(html_to_text(html), text);
        let msg = json!({
            "id": "abc", "internalDate": "0",
            "payload": {"mimeType": "text/html", "body": {"data": b64(html)}},
        });
        assert_eq!(parse_message(&msg).unwrap().body, text);
    }

    #[test]
    fn malformed_messages_are_skipped_and_fields_are_bounded() {
        for bad in [
            json!({}),
            json!({"id": "../x", "internalDate": "0", "payload": {}}),
            json!({"id": "abc", "internalDate": "soon", "payload": {}}),
            json!({"id": "abc", "internalDate": "0"}),
        ] {
            assert!(parse_message(&bad).is_none(), "accepted {bad}");
        }
        let long = "x".repeat(MAX_BODY_CHARS + 10);
        let msg = gmail_message("abc", &"s\u{7}".repeat(2000), &long);
        let p = parse_message(&msg).unwrap();
        assert_eq!(p.summary.subject.chars().count(), MAX_SUBJECT_CHARS);
        assert!(!p.summary.subject.contains('\u{7}'));
        assert!(p.body.ends_with("[message truncated]"));
    }

    #[test]
    fn unknown_or_broken_entities_are_left_alone() {
        assert_eq!(
            decode_entities("a & b &bogus; &#xZZ; &amp"),
            "a & b &bogus; &#xZZ; &amp"
        );
    }
}
