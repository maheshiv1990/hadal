//! Live mail updates for open pages, as Server-Sent Events
//! (`GET /api/mail/events`).
//!
//! An event says only *which mailbox* changed, never what arrived: the page
//! then reloads through the usual owner-scoped endpoints. Events go to the
//! mailbox owner's own streams only, and a stream ends as soon as its session
//! does (logout, idle or absolute expiry), checked without keeping the
//! session alive (CASA 2.2.x, 3.1.4).

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use actix_web::body::{BodySize, MessageBody};
use actix_web::web::Bytes;
use sqlx::PgPool;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::auth::session;

/// Most open streams one user may have (a few tabs).
const MAX_STREAMS_PER_USER: usize = 5;
/// Most open streams in all.
const MAX_STREAMS: usize = 2_000;
/// Comment line sent this often. It keeps nginx (`proxy_read_timeout 30s`)
/// and other proxies from closing a quiet stream, and is when the session is
/// checked again.
#[cfg(not(test))]
const PING_EVERY: Duration = Duration::from_secs(20);
#[cfg(test)]
const PING_EVERY: Duration = Duration::from_millis(50);
/// How long the browser waits before reconnecting a dropped stream.
const RETRY_MS: u32 = 5_000;

/// Who to tell when a mailbox changes. Cheap to clone; all clones share it.
#[derive(Clone, Default)]
pub struct MailEvents {
    streams: Arc<Mutex<HashMap<Uuid, Vec<mpsc::Sender<Uuid>>>>>,
}

impl MailEvents {
    /// Registers a stream for `owner`. `None` if they, or everyone together,
    /// already have as many open as allowed.
    fn subscribe(&self, owner: Uuid) -> Option<mpsc::Receiver<Uuid>> {
        let mut streams = self.streams.lock().ok()?;
        streams.retain(|_, senders| {
            senders.retain(|s| !s.is_closed());
            !senders.is_empty()
        });
        let total: usize = streams.values().map(Vec::len).sum();
        let mine = streams.entry(owner).or_default();
        if mine.len() >= MAX_STREAMS_PER_USER || total >= MAX_STREAMS {
            return None;
        }
        let (tx, rx) = mpsc::channel(16);
        mine.push(tx);
        Some(rx)
    }

    /// Tells `owner`'s open pages that their mailbox `account` changed. A
    /// page too slow to keep up misses the event; its next one reloads all.
    pub fn publish(&self, owner: Uuid, account: Uuid) {
        let Ok(mut streams) = self.streams.lock() else {
            return;
        };
        if let Some(senders) = streams.get_mut(&owner) {
            senders.retain(|s| !s.is_closed());
            for s in senders.iter() {
                let _ = s.try_send(account);
            }
        }
    }
}

/// Starts `owner`'s event stream for the session `token_hash`. `None` if
/// they have too many open already.
pub fn open_stream(
    events: &MailEvents,
    pool: PgPool,
    owner: Uuid,
    token_hash: Vec<u8>,
    idle_secs: u32,
) -> Option<EventStream> {
    let mut changes = events.subscribe(owner)?;
    let (out, body) = mpsc::channel::<Bytes>(16);
    actix_web::rt::spawn(async move {
        if out
            .send(Bytes::from(format!("retry: {RETRY_MS}\n\n")))
            .await
            .is_err()
        {
            return;
        }
        let mut ping = tokio::time::interval(PING_EVERY);
        ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ping.tick().await;
        loop {
            let chunk = tokio::select! {
                changed = changes.recv() => match changed {
                    Some(account) => {
                        let data = serde_json::json!({ "account": account });
                        Bytes::from(format!("event: mail\ndata: {data}\n\n"))
                    }
                    None => break,
                },
                _ = ping.tick() => {
                    match session::is_live(&pool, &token_hash, idle_secs).await {
                        Ok(true) => Bytes::from_static(b": ping\n\n"),
                        // Signed out, expired, or can't tell: end the stream.
                        // The browser reconnects, and only a live session
                        // gets a new one.
                        _ => break,
                    }
                }
                () = out.closed() => break,
            };
            if out.send(chunk).await.is_err() {
                break;
            }
        }
    });
    Some(EventStream(body))
}

/// The response body of an event stream: whatever its task sends, until the
/// task ends or the client goes away (which drops this and stops the task).
pub struct EventStream(mpsc::Receiver<Bytes>);

impl MessageBody for EventStream {
    type Error = std::convert::Infallible;

    fn size(&self) -> BodySize {
        BodySize::Stream
    }

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Bytes, Self::Error>>> {
        self.get_mut().0.poll_recv(cx).map(|chunk| chunk.map(Ok))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[actix_web::test]
    async fn events_reach_only_the_owners_streams() {
        let events = MailEvents::default();
        let (ada, bob, account) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let mut a = events.subscribe(ada).unwrap();
        let mut b = events.subscribe(bob).unwrap();
        events.publish(ada, account);
        assert_eq!(a.recv().await, Some(account));
        assert!(b.try_recv().is_err(), "another user's stream got the event");
    }

    #[actix_web::test]
    async fn streams_per_user_are_capped_and_closed_ones_free_a_slot() {
        let events = MailEvents::default();
        let owner = Uuid::new_v4();
        let mut open: Vec<_> = (0..MAX_STREAMS_PER_USER)
            .map(|_| events.subscribe(owner).unwrap())
            .collect();
        assert!(events.subscribe(owner).is_none());
        assert!(
            events.subscribe(Uuid::new_v4()).is_some(),
            "others unaffected"
        );
        drop(open.pop());
        assert!(events.subscribe(owner).is_some());
    }
}
