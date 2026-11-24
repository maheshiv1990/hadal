-- The notes feature is removed. Drop its table (and, with it, its index and
-- the owner foreign key) so no user content is left behind unused.
DROP TABLE IF EXISTS notes;
