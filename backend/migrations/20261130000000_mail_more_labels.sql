-- More of Gmail's labels: Important, Spam, the four inbox categories, and
-- the user's own labels (CASA 3.1.4, 6.7.1).

-- mail_messages.labels may now also hold these system labels and user label
-- IDs. IDs are opaque ("Label_12"); the names live encrypted in mail_labels.
ALTER TABLE mail_messages DROP CONSTRAINT mail_messages_labels_check;
ALTER TABLE mail_messages ADD CONSTRAINT mail_messages_labels_check CHECK (
    array_to_string(labels, ',') ~ ('^((INBOX|STARRED|SENT|DRAFT|IMPORTANT|SPAM'
        || '|CATEGORY_SOCIAL|CATEGORY_UPDATES|CATEGORY_FORUMS|CATEGORY_PROMOTIONS'
        || '|Label_[A-Za-z0-9_-]{1,64})(,|$))*$')
);

-- The user's own Gmail labels per mailbox, refreshed on every import. The
-- name is the user's content, so it is encrypted and bound to its row.
CREATE TABLE mail_labels (
    account_id     UUID NOT NULL,
    owner_id       UUID NOT NULL,
    gmail_label_id TEXT NOT NULL CHECK (gmail_label_id ~ '^Label_[A-Za-z0-9_-]{1,64}$'),
    name_enc       BYTEA NOT NULL,
    -- Gmail's background colour for the label, if it has one.
    color          TEXT CHECK (color ~ '^#[0-9a-f]{6}$'),
    PRIMARY KEY (account_id, gmail_label_id),
    FOREIGN KEY (account_id, owner_id)
        REFERENCES mail_accounts (id, owner_id) ON DELETE CASCADE
);
