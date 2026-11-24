-- Email + password accounts next to Google accounts (CASA 1.1.3).
--
-- The two kinds are separate: a password account and a Google account with
-- the same address are different users. Registration emails aren't verified,
-- so linking them by address would let anyone claim someone's Google account.

ALTER TABLE users ALTER COLUMN google_sub DROP NOT NULL;

ALTER TABLE users
    ADD COLUMN first_name    TEXT CHECK (char_length(first_name) BETWEEN 1 AND 100),
    ADD COLUMN last_name     TEXT CHECK (char_length(last_name) BETWEEN 1 AND 100),
    -- Argon2id PHC string; never the password itself.
    ADD COLUMN password_hash TEXT CHECK (password_hash LIKE '$argon2id$%'),
    -- Each user signs in exactly one way.
    ADD CONSTRAINT users_one_sign_in_method
        CHECK ((google_sub IS NULL) <> (password_hash IS NULL)),
    -- Password accounts store the email lower-cased, so lookups are exact.
    ADD CONSTRAINT users_password_email_lowercase
        CHECK (password_hash IS NULL OR email = lower(email));

CREATE UNIQUE INDEX users_password_email_idx ON users (email) WHERE password_hash IS NOT NULL;
