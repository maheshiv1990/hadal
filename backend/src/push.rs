//! Gmail push notifications: new mail is synced as soon as Gmail says a
//! mailbox changed, instead of waiting for the next import.
//!
//! - Gmail publishes "mailbox X changed" to our Cloud Pub/Sub topic for each
//!   watched mailbox (`users.watch`); Pub/Sub delivers it to
//!   `POST /api/gmail/push` with a token Google signs (`routes/push.rs`).
//! - The notification only names the mailbox. Its sync reads what changed
//!   from Gmail itself, from where the last one stopped (`mail::sync_account`),
//!   so a lost or repeated notification costs nothing: the next one catches up.
//! - Syncs run here, in the background, a few at a time, at most one per
//!   mailbox, with notifications that arrive meanwhile folded into one more.
//!   Open pages hear about it through `events::MailEvents`.
//! - An hourly pass renews watches (they lapse after 7 days), stops them for
//!   users who haven't signed in for a while, and syncs mailboxes that have
//!   been quiet, since Gmail may drop notifications.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use crate::auth::google::GoogleClient;
use crate::config::GmailPushConfig;
use crate::crypto::DataCipher;
use crate::events::MailEvents;
use crate::mail::{self, MailboxRef, Synced};

/// Mailbox syncs running at once.
const SYNC_CONCURRENCY: usize = 4;
/// Notifications waiting for the worker. More than this at once are dropped
/// (and logged); the quiet-mailbox pass catches those mailboxes up.
const QUEUE_LEN: usize = 1_000;
/// A mailbox an import is busy with is tried again after this.
const BUSY_RETRY: Duration = Duration::from_secs(15);
/// How often watches are renewed and quiet mailboxes synced.
const MAINTENANCE_EVERY: Duration = Duration::from_secs(60 * 60);
/// A watched mailbox with no sync for this long is synced anyway.
const QUIET_SECS: f64 = 6.0 * 60.0 * 60.0;

/// Push settings and the way into the sync worker. In app data only when
/// push is configured: without it, `/api/gmail/push` is a 404.
pub struct Push {
    pub config: GmailPushConfig,
    queue: mpsc::Sender<MailboxRef>,
}

impl Push {
    /// Asks for a sync of `mailbox`. Never waits: with the queue full the
    /// request is dropped, and the quiet-mailbox pass picks the mailbox up.
    pub fn enqueue(&self, mailbox: MailboxRef) {
        if self.queue.try_send(mailbox).is_err() {
            tracing::warn!(account = %mailbox.account, "sync queue full; mailbox left for the next pass");
        }
    }

    /// A `Push` whose queue the test reads instead of a worker.
    #[cfg(test)]
    pub fn for_test(config: GmailPushConfig) -> (Self, mpsc::Receiver<MailboxRef>) {
        let (queue, rx) = mpsc::channel(QUEUE_LEN);
        (Self { config, queue }, rx)
    }
}

/// What the worker and the hourly pass need.
#[derive(Clone)]
pub struct Syncer {
    pub pool: PgPool,
    pub google: Arc<GoogleClient>,
    pub cipher: Arc<DataCipher>,
    pub events: MailEvents,
}

/// Starts the sync worker and the hourly pass.
pub fn start(syncer: Syncer, config: GmailPushConfig) -> Push {
    let (queue, rx) = mpsc::channel(QUEUE_LEN);
    actix_web::rt::spawn(run_worker(syncer.clone(), rx, queue.clone()));
    {
        let (syncer, config, queue) = (syncer, config.clone(), queue.clone());
        actix_web::rt::spawn(async move {
            // The first pass a minute after start-up, then every hour.
            let first = tokio::time::Instant::now() + Duration::from_secs(60);
            let mut tick = tokio::time::interval_at(first, MAINTENANCE_EVERY);
            loop {
                tick.tick().await;
                maintain(&syncer, &config, &queue).await;
            }
        });
    }
    Push { config, queue }
}

/// Starts watching `owner`'s mailboxes if they aren't yet, and syncs the
/// ones never imported. Run after they import, which also means they are
/// active.
pub async fn watch_owner(syncer: &Syncer, push: &Push, owner: uuid::Uuid) {
    match mail::renew_watches(
        &syncer.pool,
        &syncer.google,
        &syncer.cipher,
        &push.config.topic,
        push.config.active_days,
        Some(owner),
    )
    .await
    {
        Ok(unsynced) => unsynced.into_iter().for_each(|m| push.enqueue(m)),
        Err(e) => tracing::warn!(error = ?e, "starting Gmail watches failed"),
    }
}

async fn maintain(syncer: &Syncer, config: &GmailPushConfig, queue: &mpsc::Sender<MailboxRef>) {
    let Syncer {
        pool,
        google,
        cipher,
        ..
    } = syncer;
    if let Err(e) = mail::stop_idle_watches(pool, google, cipher, config.active_days).await {
        tracing::warn!(error = ?e, "stopping idle Gmail watches failed");
    }
    let mut due = Vec::new();
    match mail::renew_watches(
        pool,
        google,
        cipher,
        &config.topic,
        config.active_days,
        None,
    )
    .await
    {
        Ok(unsynced) => due.extend(unsynced),
        Err(e) => tracing::warn!(error = ?e, "renewing Gmail watches failed"),
    }
    match mail::quiet_mailboxes(pool, QUIET_SECS).await {
        Ok(quiet) => due.extend(quiet),
        Err(e) => tracing::warn!(error = ?e, "listing quiet mailboxes failed"),
    }
    for mailbox in due {
        if queue.try_send(mailbox).is_err() {
            tracing::warn!("sync queue full; the rest wait for the next pass");
            break;
        }
    }
}

/// Runs syncs as they're asked for: `SYNC_CONCURRENCY` at a time, one at a
/// time per mailbox. A request for a mailbox already syncing runs once more
/// after it, however many arrive meanwhile.
async fn run_worker(
    syncer: Syncer,
    mut requests: mpsc::Receiver<MailboxRef>,
    retry: mpsc::Sender<MailboxRef>,
) {
    let mut waiting: VecDeque<MailboxRef> = VecDeque::new();
    let mut running: HashMap<tokio::task::Id, MailboxRef> = HashMap::new();
    let mut again: HashSet<MailboxRef> = HashSet::new();
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            request = requests.recv() => {
                let Some(mailbox) = request else { break };
                if running.values().any(|m| *m == mailbox) {
                    again.insert(mailbox);
                } else if !waiting.contains(&mailbox) {
                    waiting.push_back(mailbox);
                }
            }
            Some(done) = tasks.join_next_with_id(), if !tasks.is_empty() => {
                let (id, outcome) = match done {
                    Ok((id, outcome)) => (id, Some(outcome)),
                    Err(e) => {
                        tracing::error!(error = %e, "mailbox sync task failed");
                        (e.id(), None)
                    }
                };
                let Some(mailbox) = running.remove(&id) else { continue };
                match outcome {
                    Some(Ok(Synced::Changed)) => {
                        syncer.events.publish(mailbox.owner, mailbox.account);
                    }
                    Some(Ok(Synced::Busy)) => {
                        let retry = retry.clone();
                        actix_web::rt::spawn(async move {
                            tokio::time::sleep(BUSY_RETRY).await;
                            let _ = retry.try_send(mailbox);
                        });
                    }
                    Some(Ok(Synced::Unchanged | Synced::Skipped)) | None => {}
                    Some(Err(e)) => {
                        tracing::warn!(account = %mailbox.account, error = ?e, "mailbox sync failed");
                    }
                }
                if again.remove(&mailbox) {
                    waiting.push_back(mailbox);
                }
            }
        }
        while tasks.len() < SYNC_CONCURRENCY {
            let Some(mailbox) = waiting.pop_front() else {
                break;
            };
            let s = syncer.clone();
            let handle = tasks.spawn(async move {
                mail::sync_account(&s.pool, s.google, s.cipher, mailbox.owner, mailbox.account)
                    .await
            });
            running.insert(handle.id(), mailbox);
        }
    }
}
