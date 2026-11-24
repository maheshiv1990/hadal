-- Which of the folders Hadal shows (Inbox, Starred, Sent, Drafts) each
-- imported message is in, from Gmail's system labels.
--
-- Kept in the clear, like received_at, so the server can filter and count by
-- folder. It is limited to these four fixed values and holds no message
-- content. NULL means the message was imported before labels were recorded;
-- the next import fills it in, and until then it is treated as Inbox.
ALTER TABLE mail_messages
    ADD COLUMN labels TEXT[]
        CHECK (labels <@ ARRAY['INBOX', 'STARRED', 'SENT', 'DRAFT']::TEXT[]);
