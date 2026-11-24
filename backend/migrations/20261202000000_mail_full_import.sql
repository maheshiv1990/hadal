-- Import whole mailboxes, a step per import request (CASA 3.1.4: still
-- scoped by owner through mail_accounts).
--
-- After the newest mail, each import walks older mail one Gmail list page at
-- a time and saves where it stopped. The page token is Gmail's opaque list
-- cursor for this mailbox: not a credential, it grants nothing without the
-- account's access token.
ALTER TABLE mail_accounts
    ADD COLUMN backfill_page_token TEXT
        CHECK (char_length(backfill_page_token) BETWEEN 1 AND 256),
    -- The walk reached the oldest message. Reset when new mail outruns the
    -- newest-mail step, so nothing is left out.
    ADD COLUMN backfill_done BOOLEAN NOT NULL DEFAULT false;
