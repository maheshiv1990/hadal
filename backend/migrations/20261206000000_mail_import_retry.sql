-- Gmail refused requests for this mailbox (its per-user quota): no import
-- or sync contacts Gmail for it again before this time. NULL: not held.
ALTER TABLE mail_accounts ADD COLUMN import_retry_at TIMESTAMPTZ;
