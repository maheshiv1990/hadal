-- Set once the user edits their name in Settings. Google sign-in then stops
-- copying Google's name over it; until then Google stays the source.
ALTER TABLE users ADD COLUMN name_set_by_user BOOLEAN NOT NULL DEFAULT false;
