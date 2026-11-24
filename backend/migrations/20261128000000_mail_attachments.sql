-- Attachment details for imported messages (CASA 6.7.1).
--
-- JSON [{gmail_attachment_id, filename, mime_type, size}], AES-256-GCM
-- encrypted and bound to the row like summary_enc and body_enc. The files
-- themselves are not stored: they stay at Google and are fetched only when
-- the owner downloads one. NULL means the message was imported before
-- attachments were recorded; the next import fills it in.
ALTER TABLE mail_messages ADD COLUMN attachments_enc BYTEA;
