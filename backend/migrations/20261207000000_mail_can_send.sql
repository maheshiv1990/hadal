-- Whether the user granted this mailbox the send permission (gmail.send)
-- when linking it. Mailboxes linked before sending existed have only
-- read-only access: they stay false until the user reconnects them.
ALTER TABLE mail_accounts ADD COLUMN can_send BOOLEAN NOT NULL DEFAULT false;
