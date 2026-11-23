CREATE TABLE IF NOT EXISTS notes (
    id         UUID PRIMARY KEY,
    title      TEXT NOT NULL CHECK (char_length(title) BETWEEN 1 AND 200),
    body       TEXT NOT NULL DEFAULT '' CHECK (char_length(body) <= 10000),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS notes_created_at_idx ON notes (created_at DESC);
