-- Google sign-in, server-side sessions and per-user notes (CASA 2.2.x, 3.1.1, 3.1.4).

CREATE TABLE users (
    id            UUID PRIMARY KEY,
    -- Google's stable account ID (`sub`). Email can change; this can't.
    google_sub    TEXT NOT NULL UNIQUE CHECK (char_length(google_sub) BETWEEN 1 AND 255),
    email         TEXT NOT NULL CHECK (char_length(email) BETWEEN 1 AND 320),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Only the SHA-256 of each session token is stored.
CREATE TABLE sessions (
    token_hash   BYTEA PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    user_id      UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL
);
CREATE INDEX sessions_user_id_idx ON sessions (user_id);
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);

-- Sign-ins in progress: state, nonce and PKCE verifier, keyed by the hash of
-- the login cookie. Each row is deleted when the callback uses it.
CREATE TABLE oauth_logins (
    id_hash       BYTEA PRIMARY KEY CHECK (octet_length(id_hash) = 32),
    state         TEXT NOT NULL,
    code_verifier TEXT NOT NULL,
    nonce         TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ NOT NULL
);
CREATE INDEX oauth_logins_expires_at_idx ON oauth_logins (expires_at);

-- Notes written before sign-in existed have no owner and were readable by
-- anyone. They can't be attributed to a user, so they are removed.
DELETE FROM notes;
ALTER TABLE notes ADD COLUMN owner_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE;
DROP INDEX IF EXISTS notes_created_at_idx;
CREATE INDEX notes_owner_created_idx ON notes (owner_id, created_at DESC);
