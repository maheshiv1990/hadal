-- Gmail's own message count per folder and label of a linked mailbox, read
-- at each import, so the inbox shows the mailbox's real size at once rather
-- than a count that grows while the import catches up (CASA 3.1.4: scoped
-- by owner like the mailbox it belongs to).
--
-- label_id is a Gmail system label, a user label ID, or ALL (every message
-- but spam and trash). Only IDs and counts: label names stay in mail_labels,
-- encrypted.
CREATE TABLE mail_gmail_totals (
    account_id UUID NOT NULL,
    owner_id   UUID NOT NULL,
    label_id   TEXT NOT NULL CHECK (char_length(label_id) BETWEEN 1 AND 80),
    total      BIGINT NOT NULL CHECK (total >= 0),
    PRIMARY KEY (account_id, label_id),
    FOREIGN KEY (account_id, owner_id)
        REFERENCES mail_accounts (id, owner_id) ON DELETE CASCADE
);
