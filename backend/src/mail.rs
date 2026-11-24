//! Linked Gmail mailboxes and imported mail.
//!
//! - Every query is scoped by `owner_id` from the session (CASA 3.1.4,
//!   lint:notes-owner-scope); messages also carry a foreign key to their
//!   mailbox *and* its owner, so a row can't point at someone else's mailbox.
//! - Refresh tokens and message content are encrypted with `DataCipher`, bound
//!   to their row (CASA 6.7.1). Access tokens live only in memory.
//! - Bodies are reduced to plain text here and shown as text by the frontend,
//!   so mail HTML is never rendered (CASA 5.1.7).
//! - Attachments: only their name, type, size and Gmail ID are stored
//!   (encrypted). A file is fetched from Gmail when its owner downloads it,
//!   picked by its position in our own record, never by an ID from the request.

use std::collections::HashMap;
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

use crate::auth::google::{
    GoogleApiError, GoogleClient, Identity, UserLabel, valid_attachment_id, valid_gmail_id,
    valid_user_label_id,
};
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
/// The Gmail system labels Hadal shows as folders. (Scheduled, Snoozed and
/// Purchases aren't available through the Gmail API.)
pub const SYSTEM_LABELS: [&str; 10] = [
    "INBOX",
    "STARRED",
    "SENT",
    "DRAFT",
    "IMPORTANT",
    "SPAM",
    "CATEGORY_SOCIAL",
    "CATEGORY_UPDATES",
    "CATEGORY_FORUMS",
    "CATEGORY_PROMOTIONS",
];

/// The system label lists each import reads: how many of the newest it
/// lists (to refresh labels on mail we have), and how many of those it
/// imports if we don't have them yet. The categories and Important are
/// mostly Inbox mail, so they only refresh.
const IMPORT_LISTS: [(&str, u32, usize); 10] = [
    ("INBOX", 100, 100),
    ("STARRED", 50, 50),
    ("SENT", 50, 50),
    ("DRAFT", 25, 25),
    ("SPAM", 25, 25),
    ("IMPORTANT", 100, 0),
    ("CATEGORY_SOCIAL", 100, 0),
    ("CATEGORY_UPDATES", 100, 0),
    ("CATEGORY_FORUMS", 100, 0),
    ("CATEGORY_PROMOTIONS", 100, 0),
];
/// Most of a mailbox's own labels kept, and how many of them are read on
/// each import: their newest messages are listed to refresh labels, and the
/// newest few imported so every label in the menu has mail. Labels past
/// these keep what Gmail said when each message was imported.
const MAX_USER_LABELS: usize = 100;
const REFRESHED_USER_LABELS: usize = 20;
const USER_LABEL_LIST: u32 = 100;
const USER_LABEL_IMPORT: usize = 25;

/// Whether a Gmail label ID is one Hadal keeps on a message.
fn kept_label(id: &str) -> bool {
    SYSTEM_LABELS.contains(&id) || valid_user_label_id(id)
}

/// What the message list is filtered to: every message except spam, or one
/// label (a system folder or one of the user's labels).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabelFilter {
    AllMail,
    Label(String),
}

impl LabelFilter {
    /// `ALL`, one of `SYSTEM_LABELS`, or a user label ID. Anything else is
    /// refused.
    pub fn parse(raw: &str) -> Option<Self> {
        if raw == "ALL" {
            Some(LabelFilter::AllMail)
        } else if kept_label(raw) {
            Some(LabelFilter::Label(raw.to_owned()))
        } else {
            None
        }
    }
}

/// Most attachments recorded for one message.
const MAX_ATTACHMENTS: usize = 50;
const MAX_FILENAME_CHARS: usize = 255;
const MAX_MIME_CHARS: usize = 255;
/// Gmail's own limit on attachment size.
pub const MAX_ATTACHMENT_BYTES: usize = 25 * 1024 * 1024;
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

#[derive(Serialize)]
pub struct Account {
    id: Uuid,
    email: String,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    last_import_at: Option<OffsetDateTime>,
    message_count: i64,
    /// Messages per label ID, plus `ALL` (everything but spam). Mail imported
    /// before labels were recorded counts as Inbox until the next import.
    folder_counts: HashMap<String, i64>,
    /// The mailbox's own Gmail labels, by name.
    labels: Vec<LabelInfo>,
}

#[derive(Serialize, Debug)]
pub struct LabelInfo {
    id: String,
    name: String,
    color: Option<String>,
}

fn label_aad(owner: Uuid, account: Uuid, label_id: &str) -> Vec<u8> {
    let mut aad = b"mail_labels.name\0".to_vec();
    aad.extend_from_slice(owner.as_bytes());
    aad.extend_from_slice(account.as_bytes());
    aad.extend_from_slice(label_id.as_bytes());
    aad
}

pub async fn list_accounts(
    pool: &PgPool,
    cipher: &DataCipher,
    owner: Uuid,
) -> Result<Vec<Account>, AppError> {
    let rows: Vec<(Uuid, String, OffsetDateTime, Option<OffsetDateTime>, i64)> = sqlx::query_as(
        "SELECT a.id, a.email, a.created_at, a.last_import_at, count(m.id)
           FROM mail_accounts a
           LEFT JOIN mail_messages m ON m.account_id = a.id AND m.owner_id = $1
          WHERE a.owner_id = $1
          GROUP BY a.id
          ORDER BY a.created_at",
    )
    .bind(owner)
    .fetch_all(pool)
    .await?;
    let counts: Vec<(Uuid, String, i64)> = sqlx::query_as(
        "SELECT m.account_id, l, count(*)
           FROM mail_messages m
          CROSS JOIN LATERAL unnest(coalesce(m.labels, ARRAY['INBOX']::text[])) AS l
          WHERE m.owner_id = $1
          GROUP BY m.account_id, l",
    )
    .bind(owner)
    .fetch_all(pool)
    .await?;
    let labels: Vec<(Uuid, String, Vec<u8>, Option<String>)> = sqlx::query_as(
        "SELECT account_id, gmail_label_id, name_enc, color FROM mail_labels
          WHERE owner_id = $1",
    )
    .bind(owner)
    .fetch_all(pool)
    .await?;

    rows.into_iter()
        .map(|(id, email, created_at, last_import_at, message_count)| {
            let mut folder_counts: HashMap<String, i64> = counts
                .iter()
                .filter(|c| c.0 == id)
                .map(|c| (c.1.clone(), c.2))
                .collect();
            let spam = folder_counts.get("SPAM").copied().unwrap_or(0);
            folder_counts.insert("ALL".to_owned(), message_count - spam);
            let mut mine = labels
                .iter()
                .filter(|l| l.0 == id)
                .map(|(_, label_id, sealed, color)| {
                    let name = cipher.decrypt(sealed, &label_aad(owner, id, label_id))?;
                    Ok(LabelInfo {
                        id: label_id.clone(),
                        name: String::from_utf8_lossy(&name).into_owned(),
                        color: color.clone(),
                    })
                })
                .collect::<Result<Vec<_>, AppError>>()?;
            mine.sort_by_key(|l| l.name.to_lowercase());
            Ok(Account {
                id,
                email,
                created_at,
                last_import_at,
                message_count,
                folder_counts,
                labels: mine,
            })
        })
        .collect()
}

pub enum Unlinked {
    /// Removed with its mail. Carries its refresh token (if it still
    /// decrypts) so the caller can revoke it at Google.
    Removed(Option<Secret>),
    /// The mailbox for the email the user signs in with: never unlinked.
    SignInAccount,
    /// Not one of the caller's mailboxes.
    NotFound,
}

/// Unlinks one of the caller's mailboxes and deletes its messages and labels
/// (by cascade), unless it is the mailbox for their sign-in email.
pub async fn delete_account(
    pool: &PgPool,
    cipher: &DataCipher,
    owner: Uuid,
    id: Uuid,
) -> Result<Unlinked, AppError> {
    let row: Option<(String, Vec<u8>)> = sqlx::query_as(
        "DELETE FROM mail_accounts a
          WHERE a.id = $1 AND a.owner_id = $2
            AND lower(a.email) <> (SELECT lower(u.email) FROM users u WHERE u.id = $2)
         RETURNING a.google_sub, a.refresh_token_enc",
    )
    .bind(id)
    .bind(owner)
    .fetch_optional(pool)
    .await?;
    if let Some((sub, sealed)) = row {
        // The mailbox is already gone; a token that won't decrypt just can't
        // be revoked from here.
        return Ok(Unlinked::Removed(
            open_token(cipher, owner, &sub, &sealed).ok(),
        ));
    }
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM mail_accounts WHERE id = $1 AND owner_id = $2)",
    )
    .bind(id)
    .bind(owner)
    .fetch_one(pool)
    .await?;
    Ok(if exists {
        Unlinked::SignInAccount
    } else {
        Unlinked::NotFound
    })
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

/// One attachment as recorded at import, stored encrypted. The file itself
/// stays at Google.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StoredAttachment {
    /// Gmail's ID for the file. Never sent to the client.
    pub gmail_attachment_id: String,
    pub filename: String,
    pub mime_type: String,
    pub size: u64,
}

/// What the client sees of an attachment. `index` is how it asks for it.
#[derive(Serialize, Debug)]
pub struct AttachmentInfo {
    index: usize,
    filename: String,
    mime_type: String,
    size: u64,
}

fn attachment_infos(stored: Vec<StoredAttachment>) -> Vec<AttachmentInfo> {
    stored
        .into_iter()
        .enumerate()
        .map(|(index, a)| AttachmentInfo {
            index,
            filename: a.filename,
            mime_type: a.mime_type,
            size: a.size,
        })
        .collect()
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
    attachments: Vec<AttachmentInfo>,
    /// Folder labels (INBOX, STARRED, SENT, DRAFT) the message is in.
    labels: Vec<String>,
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

/// Decrypts a message's attachment list. `None` (imported before attachments
/// were recorded) reads as no attachments.
fn open_attachments(
    cipher: &DataCipher,
    owner: Uuid,
    id: Uuid,
    sealed: Option<&[u8]>,
) -> Result<Vec<StoredAttachment>, AppError> {
    let Some(sealed) = sealed else {
        return Ok(Vec::new());
    };
    let plain = cipher.decrypt(sealed, &message_aad("attachments", owner, id))?;
    serde_json::from_slice(&plain)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("stored attachments are invalid: {e}")))
}

fn seal_attachments(
    cipher: &DataCipher,
    owner: Uuid,
    id: Uuid,
    attachments: &[StoredAttachment],
) -> Result<Vec<u8>, AppError> {
    let plain = serde_json::to_vec(attachments)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("attachment encoding failed: {e}")))?;
    cipher.encrypt(&plain, &message_aad("attachments", owner, id))
}

type ItemRow = (
    Uuid,
    Uuid,
    String,
    OffsetDateTime,
    Vec<u8>,
    Option<Vec<u8>>,
    Option<Vec<String>>,
);
type DetailRow = (
    Uuid,
    String,
    OffsetDateTime,
    Vec<u8>,
    Vec<u8>,
    Option<Vec<u8>>,
    Option<Vec<String>>,
);

/// Labels as stored; NULL (imported before labels were recorded) reads as Inbox.
fn stored_labels(labels: Option<Vec<String>>) -> Vec<String> {
    labels.unwrap_or_else(|| vec!["INBOX".to_owned()])
}

/// Newest imported messages across all of the user's mailboxes.
///
/// Optionally only one of the user's mailboxes, and only one folder. An
/// `account` that isn't the caller's simply matches nothing.
pub async fn list_messages(
    pool: &PgPool,
    cipher: &DataCipher,
    owner: Uuid,
    account: Option<Uuid>,
    filter: Option<LabelFilter>,
) -> Result<Vec<MessageItem>, AppError> {
    let (label, all_mail) = match filter {
        None => (None, false),
        Some(LabelFilter::AllMail) => (None, true),
        Some(LabelFilter::Label(l)) => (Some(l), false),
    };
    let rows: Vec<ItemRow> = sqlx::query_as(
        "SELECT m.id, m.account_id, a.email, m.received_at, m.summary_enc, m.attachments_enc,
                m.labels
           FROM mail_messages m
           JOIN mail_accounts a ON a.id = m.account_id AND a.owner_id = m.owner_id
          WHERE m.owner_id = $1
            AND ($3::uuid IS NULL OR m.account_id = $3)
            AND ($4::text IS NULL
                 OR $4 = ANY(m.labels)
                 OR (m.labels IS NULL AND $4 = 'INBOX'))
            AND (NOT $5 OR NOT ('SPAM' = ANY(coalesce(m.labels, '{}'))))
          ORDER BY m.received_at DESC
          LIMIT $2",
    )
    .bind(owner)
    .bind(LIST_LIMIT)
    .bind(account)
    .bind(label)
    .bind(all_mail)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(
            |(id, account_id, account_email, received_at, sealed, attachments, labels)| {
                Ok(MessageItem {
                    id,
                    account_id,
                    account_email,
                    received_at,
                    summary: open_summary(cipher, owner, id, &sealed)?,
                    attachments: attachment_infos(open_attachments(
                        cipher,
                        owner,
                        id,
                        attachments.as_deref(),
                    )?),
                    labels: stored_labels(labels),
                })
            },
        )
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
        "SELECT m.account_id, a.email, m.received_at, m.summary_enc, m.body_enc,
                m.attachments_enc, m.labels
           FROM mail_messages m
           JOIN mail_accounts a ON a.id = m.account_id AND a.owner_id = m.owner_id
          WHERE m.id = $1 AND m.owner_id = $2",
    )
    .bind(id)
    .bind(owner)
    .fetch_optional(pool)
    .await?;
    let Some((account_id, account_email, received_at, summary, body, attachments, labels)) = row
    else {
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
            attachments: attachment_infos(open_attachments(
                cipher,
                owner,
                id,
                attachments.as_deref(),
            )?),
            labels: stored_labels(labels),
        },
        body: String::from_utf8_lossy(&body).into_owned(),
    }))
}

// ---- downloading an attachment ---------------------------------------------

/// A downloaded attachment: its recorded name and type, and the file.
pub struct Download {
    pub filename: String,
    pub bytes: Vec<u8>,
}

type DownloadRow = (String, Option<Vec<u8>>, String, Vec<u8>);

/// Fetches attachment `index` of the caller's message from Gmail. `None` if
/// the message isn't the caller's or has no such attachment. The Gmail IDs
/// come from our own encrypted records, never from the request.
pub async fn download_attachment(
    pool: &PgPool,
    google: &GoogleClient,
    cipher: &DataCipher,
    owner: Uuid,
    message_id: Uuid,
    index: usize,
) -> Result<Option<Download>, AppError> {
    let row: Option<DownloadRow> = sqlx::query_as(
        "SELECT m.gmail_id, m.attachments_enc, a.google_sub, a.refresh_token_enc
           FROM mail_messages m
           JOIN mail_accounts a ON a.id = m.account_id AND a.owner_id = m.owner_id
          WHERE m.id = $1 AND m.owner_id = $2",
    )
    .bind(message_id)
    .bind(owner)
    .fetch_optional(pool)
    .await?;
    let Some((gmail_id, sealed_attachments, google_sub, sealed_token)) = row else {
        return Ok(None);
    };
    let Some(attachment) =
        open_attachments(cipher, owner, message_id, sealed_attachments.as_deref())?
            .into_iter()
            .nth(index)
    else {
        return Ok(None);
    };

    let gmail_failed = |e: GoogleApiError| {
        // The file name is mail content: it is not logged.
        tracing::warn!(message = %message_id, error = %e, "attachment download failed");
        match e {
            GoogleApiError::Revoked => {
                AppError::Upstream("Google access was revoked or expired. Reconnect this mailbox.")
            }
            ref e if e.is_rate_limited() => AppError::Upstream(
                "Gmail is limiting requests right now. Wait a minute and try again.",
            ),
            _ => AppError::Upstream("Could not get this attachment from Gmail. Try again."),
        }
    };
    let refresh = open_token(cipher, owner, &google_sub, &sealed_token)?;
    let access = google
        .refresh_access_token(&refresh)
        .await
        .map_err(gmail_failed)?;
    let data = google
        .get_attachment(&access, &gmail_id, &attachment.gmail_attachment_id)
        .await
        .map_err(gmail_failed)?;
    let bytes = GMAIL_BASE64
        .decode(data.trim())
        .map_err(|_| gmail_failed(GoogleApiError::Malformed))?;
    if bytes.len() > MAX_ATTACHMENT_BYTES {
        return Err(gmail_failed(GoogleApiError::Malformed));
    }
    Ok(Some(Download {
        filename: attachment.filename,
        bytes,
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
            ImportFailure::Google(e) if e.is_rate_limited() => {
                "Gmail is limiting requests right now. Wait a minute, then import again."
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
    let user_labels = google.list_user_labels(&access, MAX_USER_LABELS).await?;
    store_labels(pool, cipher, owner, account.id, &user_labels).await?;

    // The newest mail overall, plus the newest of each folder, so sent mail,
    // drafts and spam show up even when they aren't among the newest overall.
    // Category, Important and user-label lists only refresh labels.
    let (mut ids, _) = google
        .list_message_ids(&access, IMPORT_PER_MAILBOX, None)
        .await?;
    let lists = IMPORT_LISTS
        .iter()
        .map(|&(label, max, import)| (label.to_owned(), max, import))
        .chain(
            user_labels
                .iter()
                .take(REFRESHED_USER_LABELS)
                .map(|l| (l.id.clone(), USER_LABEL_LIST, USER_LABEL_IMPORT)),
        );
    let mut folder_lists = Vec::new();
    for (label, max, import) in lists {
        let (listed, complete) = google.list_message_ids(&access, max, Some(&label)).await?;
        for id in listed.iter().take(import) {
            if !ids.contains(id) {
                ids.push(id.clone());
            }
        }
        folder_lists.push((label, listed, complete));
    }

    // Already stored: skipped, unless stored before attachments or labels
    // were recorded, in which case it is fetched again to fill them in.
    let known: Vec<(String, Uuid, bool)> = sqlx::query_as(
        "SELECT gmail_id, id, attachments_enc IS NOT NULL AND labels IS NOT NULL
           FROM mail_messages
          WHERE owner_id = $1 AND account_id = $2 AND gmail_id = ANY($3)",
    )
    .bind(owner)
    .bind(account.id)
    .bind(&ids)
    .fetch_all(pool)
    .await?;
    let complete: Vec<&str> = known.iter().filter(|k| k.2).map(|k| k.0.as_str()).collect();
    let backfill: HashMap<String, Uuid> = known
        .iter()
        .filter(|k| !k.2)
        .map(|k| (k.0.clone(), k.1))
        .collect();
    let mut pending = ids
        .into_iter()
        .filter(|id| !complete.contains(&id.as_str()))
        .collect::<Vec<_>>()
        .into_iter();

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
        if let Some(&existing) = backfill.get(&parsed.gmail_id) {
            fill_details(pool, cipher, owner, existing, &parsed).await?;
        } else if store_message(pool, cipher, owner, account.id, &parsed).await? {
            imported.fetch_add(1, Ordering::Relaxed);
        }
    }

    // Starring, sending or archiving in Gmail changes labels on mail we
    // already have: bring those up to date from the folder lists.
    for (label, listed, complete) in folder_lists {
        refresh_label(pool, owner, account.id, &label, &listed, complete).await?;
    }
    Ok(())
}

/// Stores the mailbox's own labels as Gmail has them now: names encrypted,
/// labels deleted in Gmail removed here too.
async fn store_labels(
    pool: &PgPool,
    cipher: &DataCipher,
    owner: Uuid,
    account_id: Uuid,
    labels: &[UserLabel],
) -> Result<(), AppError> {
    let ids: Vec<&str> = labels.iter().map(|l| l.id.as_str()).collect();
    sqlx::query(
        "DELETE FROM mail_labels
          WHERE owner_id = $1 AND account_id = $2 AND NOT (gmail_label_id = ANY($3))",
    )
    .bind(owner)
    .bind(account_id)
    .bind(&ids)
    .execute(pool)
    .await?;
    for label in labels {
        let sealed = cipher.encrypt(
            label.name.as_bytes(),
            &label_aad(owner, account_id, &label.id),
        )?;
        sqlx::query(
            "INSERT INTO mail_labels (account_id, owner_id, gmail_label_id, name_enc, color)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (account_id, gmail_label_id) DO UPDATE SET
                 name_enc = EXCLUDED.name_enc,
                 color = EXCLUDED.color
             WHERE mail_labels.owner_id = EXCLUDED.owner_id",
        )
        .bind(account_id)
        .bind(owner)
        .bind(&label.id)
        .bind(sealed)
        .bind(&label.color)
        .execute(pool)
        .await?;
    }
    Ok(())
}

/// Adds `label` to stored messages Gmail listed in it, and removes
/// it from stored messages Gmail did not list. Gmail lists newest first, so
/// a message newer than the oldest listed one that we hold is known not to
/// be in the folder; if the list was complete, every unlisted one is.
async fn refresh_label(
    pool: &PgPool,
    owner: Uuid,
    account_id: Uuid,
    label: &str,
    listed: &[String],
    complete: bool,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE mail_messages SET labels = array_append(labels, $4)
          WHERE owner_id = $1 AND account_id = $2 AND gmail_id = ANY($3)
            AND labels IS NOT NULL AND NOT ($4 = ANY(labels))",
    )
    .bind(owner)
    .bind(account_id)
    .bind(listed)
    .bind(label)
    .execute(pool)
    .await?;
    sqlx::query(
        "UPDATE mail_messages SET labels = array_remove(labels, $4)
          WHERE owner_id = $1 AND account_id = $2
            AND labels IS NOT NULL AND $4 = ANY(labels)
            AND NOT (gmail_id = ANY($3))
            AND ($5 OR received_at > (
                SELECT min(received_at) FROM mail_messages
                 WHERE owner_id = $1 AND account_id = $2 AND gmail_id = ANY($3)))",
    )
    .bind(owner)
    .bind(account_id)
    .bind(listed)
    .bind(label)
    .bind(complete)
    .execute(pool)
    .await?;
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
    let attachments = seal_attachments(cipher, owner, id, &msg.attachments)?;
    let result = sqlx::query(
        "INSERT INTO mail_messages
             (id, owner_id, account_id, gmail_id, received_at, summary_enc, body_enc,
              attachments_enc, labels)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         ON CONFLICT (account_id, gmail_id) DO NOTHING",
    )
    .bind(id)
    .bind(owner)
    .bind(account_id)
    .bind(&msg.gmail_id)
    .bind(msg.received_at)
    .bind(summary)
    .bind(body)
    .bind(attachments)
    .bind(&msg.labels)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Records the attachments and labels of a message imported before they
/// were recorded. Sealed under the existing row's ID, which the ciphertext is
/// bound to.
async fn fill_details(
    pool: &PgPool,
    cipher: &DataCipher,
    owner: Uuid,
    id: Uuid,
    msg: &Parsed,
) -> Result<(), AppError> {
    let sealed = seal_attachments(cipher, owner, id, &msg.attachments)?;
    sqlx::query(
        "UPDATE mail_messages SET attachments_enc = $3, labels = $4
          WHERE id = $1 AND owner_id = $2
            AND (attachments_enc IS NULL OR labels IS NULL)",
    )
    .bind(id)
    .bind(owner)
    .bind(sealed)
    .bind(&msg.labels)
    .execute(pool)
    .await?;
    Ok(())
}

// ---- parsing Gmail messages -------------------------------------------------

#[derive(Debug)]
pub struct Parsed {
    pub gmail_id: String,
    pub received_at: OffsetDateTime,
    pub summary: Summary,
    pub body: String,
    pub attachments: Vec<StoredAttachment>,
    /// Which of our folders' labels the message carries.
    pub labels: Vec<String>,
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
    let mut attachments = Vec::new();
    collect_attachments(payload, 0, &mut attachments);
    Some(Parsed {
        gmail_id: gmail_id.to_owned(),
        received_at,
        summary,
        body: cap_body(body),
        attachments,
        labels: msg
            .get("labelIds")
            .and_then(Value::as_array)
            .map(|ids| {
                let mut kept: Vec<String> = Vec::new();
                for id in ids.iter().filter_map(Value::as_str) {
                    if kept_label(id) && !kept.iter().any(|k| k == id) {
                        kept.push(id.to_owned());
                    }
                }
                kept
            })
            .unwrap_or_default(),
    })
}

/// A part's header value, matched case-insensitively.
fn part_header<'a>(part: &'a Value, name: &str) -> Option<&'a str> {
    part.get("headers")?
        .as_array()?
        .iter()
        .find(|h| {
            h.get("name")
                .and_then(Value::as_str)
                .is_some_and(|n| n.eq_ignore_ascii_case(name))
        })?
        .get("value")?
        .as_str()
}

/// Collects the parts that are real attachments: a file name and a Gmail
/// attachment ID. Images embedded in an HTML body (a Content-ID, not marked
/// as an attachment) are left out, as mail apps do.
fn collect_attachments(part: &Value, depth: u8, out: &mut Vec<StoredAttachment>) {
    if depth > 16 || out.len() >= MAX_ATTACHMENTS {
        return;
    }
    // Gmail gives every attachment a file name; inline body parts have "".
    let filename = part
        .get("filename")
        .and_then(Value::as_str)
        .filter(|f| !f.trim().is_empty())
        .map(|f| Some(clean_filename(f)).filter(|c| !c.is_empty()))
        .map(|c| c.unwrap_or_else(|| "attachment".to_owned()))
        .unwrap_or_default();
    let attachment_id = part
        .get("body")
        .and_then(|b| b.get("attachmentId"))
        .and_then(Value::as_str)
        .filter(|id| valid_attachment_id(id));
    let embedded = part_header(part, "Content-ID").is_some()
        && !part_header(part, "Content-Disposition").is_some_and(|d| {
            d.trim_start()
                .to_ascii_lowercase()
                .starts_with("attachment")
        });
    if let Some(id) = attachment_id
        && !filename.is_empty()
        && !embedded
    {
        out.push(StoredAttachment {
            gmail_attachment_id: id.to_owned(),
            filename,
            mime_type: part
                .get("mimeType")
                .and_then(Value::as_str)
                .map(|m| clean_line(m, MAX_MIME_CHARS).to_ascii_lowercase())
                .filter(|m| !m.is_empty())
                .unwrap_or_else(|| "application/octet-stream".to_owned()),
            size: part
                .get("body")
                .and_then(|b| b.get("size"))
                .and_then(Value::as_u64)
                .unwrap_or(0),
        });
    }
    if let Some(parts) = part.get("parts").and_then(Value::as_array) {
        for p in parts {
            collect_attachments(p, depth + 1, out);
        }
    }
}

/// A file name that is safe to show and to offer as a download name: no
/// control characters, no path separators, no leading dots, bounded length.
fn clean_filename(raw: &str) -> String {
    let name: String = clean_line(raw, MAX_FILENAME_CHARS)
        .chars()
        .map(|c| if c == '/' || c == '\\' { '_' } else { c })
        .collect();
    name.trim_start_matches(['.', ' ']).trim_end().to_owned()
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
            "labelIds": ["INBOX", "UNREAD"],
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
        assert_eq!(p.labels, ["INBOX"], "only labels Hadal shows are kept");
        let mut msg = gmail_message("abc", "s", "t");
        msg["labelIds"] = json!(["Label_3", "UNREAD", "SPAM", "Label_3", "Label_../x", "CHAT"]);
        assert_eq!(parse_message(&msg).unwrap().labels, ["Label_3", "SPAM"]);
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
    fn attachments_are_recorded_without_embedded_images_or_unsafe_names() {
        let msg = json!({
            "id": "abc", "internalDate": "0",
            "payload": {"mimeType": "multipart/mixed", "parts": [
                {"mimeType": "multipart/related", "parts": [
                    {"mimeType": "text/html", "filename": "", "body": {"data": b64("<p>hi</p>")}},
                    // Embedded in the HTML body: not a user-facing attachment.
                    {"mimeType": "image/png", "filename": "logo.png",
                     "headers": [{"name": "Content-ID", "value": "<logo>"},
                                 {"name": "Content-Disposition", "value": "inline"}],
                     "body": {"attachmentId": "img1", "size": 100}},
                ]},
                {"mimeType": "application/PDF", "filename": "../../Q3\u{7}/report.pdf",
                 "headers": [{"name": "Content-ID", "value": "<x>"},
                             {"name": "content-disposition", "value": "Attachment; filename=x"}],
                 "body": {"attachmentId": "pdf_1-A", "size": 2048}},
                {"mimeType": "text/plain", "filename": "...",
                 "body": {"attachmentId": "dots", "size": 1}},
                // No attachment ID we could ever fetch: skipped.
                {"mimeType": "text/plain", "filename": "bad.txt",
                 "body": {"attachmentId": "../../messages", "size": 1}},
                {"mimeType": "text/plain", "filename": "inline-data.txt",
                 "body": {"data": b64("x"), "size": 1}},
            ]},
        });
        let p = parse_message(&msg).unwrap();
        assert_eq!(
            p.attachments,
            vec![
                StoredAttachment {
                    gmail_attachment_id: "pdf_1-A".into(),
                    filename: "_.._Q3 _report.pdf".into(),
                    mime_type: "application/pdf".into(),
                    size: 2048,
                },
                StoredAttachment {
                    gmail_attachment_id: "dots".into(),
                    filename: "attachment".into(),
                    mime_type: "text/plain".into(),
                    size: 1,
                },
            ]
        );
        assert_eq!(p.body, "hi");
    }

    #[test]
    fn unknown_or_broken_entities_are_left_alone() {
        assert_eq!(
            decode_entities("a & b &bogus; &#xZZ; &amp"),
            "a & b &bogus; &#xZZ; &amp"
        );
    }
}
