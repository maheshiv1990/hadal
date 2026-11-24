-- Linked Gmail mailboxes and their imported messages (CASA 3.1.4, 6.7.1).
--
-- Refresh tokens and message content are AES-256-GCM ciphertext
-- (backend/src/crypto.rs); the key never reaches the database. Only what is
-- needed to order and de-duplicate messages is stored in the clear.

-- A pending Google authorization started by a signed-in user to link a
-- mailbox, rather than to sign in. NULL means sign-in.
ALTER TABLE oauth_logins
    ADD COLUMN link_user_id UUID REFERENCES users (id) ON DELETE CASCADE;

CREATE TABLE mail_accounts (
    id                UUID PRIMARY KEY,
    owner_id          UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- Google's stable ID for the linked account; email is for display.
    google_sub        TEXT NOT NULL CHECK (char_length(google_sub) BETWEEN 1 AND 255),
    email             TEXT NOT NULL CHECK (char_length(email) BETWEEN 1 AND 320),
    refresh_token_enc BYTEA NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_import_at    TIMESTAMPTZ,
    -- Set while an import runs, so two imports of one mailbox can't overlap.
    import_started_at TIMESTAMPTZ,
    UNIQUE (owner_id, google_sub),
    -- Target of the composite foreign key below.
    UNIQUE (id, owner_id)
);

CREATE TABLE mail_messages (
    id          UUID PRIMARY KEY,
    owner_id    UUID NOT NULL,
    account_id  UUID NOT NULL,
    gmail_id    TEXT NOT NULL CHECK (char_length(gmail_id) BETWEEN 1 AND 64),
    received_at TIMESTAMPTZ NOT NULL,
    -- JSON {from, to, subject, date, snippet}, encrypted.
    summary_enc BYTEA NOT NULL,
    -- Plain-text body, encrypted.
    body_enc    BYTEA NOT NULL,
    imported_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- A message always belongs to the owner of its mailbox.
    FOREIGN KEY (account_id, owner_id)
        REFERENCES mail_accounts (id, owner_id) ON DELETE CASCADE,
    UNIQUE (account_id, gmail_id)
);
CREATE INDEX mail_messages_owner_received_idx ON mail_messages (owner_id, received_at DESC);
