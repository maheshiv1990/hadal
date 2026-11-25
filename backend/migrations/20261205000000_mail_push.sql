-- Gmail push notifications (users.watch + Cloud Pub/Sub).

-- Where the mailbox's change history was last read up to (Gmail's
-- historyId, an unsigned 64-bit number as text). NULL until the first
-- import, or after Gmail said the history is too old: the next sync then
-- imports instead of reading history.
ALTER TABLE mail_accounts
    ADD COLUMN history_id TEXT CHECK (history_id ~ '^[0-9]{1,20}$'),
    -- When Gmail stops sending notifications for this mailbox unless the
    -- watch is renewed. NULL: not watched (never, or its owner hasn't signed
    -- in for a while).
    ADD COLUMN watch_expires_at TIMESTAMPTZ;

-- A notification names the mailbox by address.
CREATE INDEX mail_accounts_email_idx ON mail_accounts (lower(email));
