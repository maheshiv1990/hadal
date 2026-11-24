-- Read and unread mail, from Gmail's UNREAD label.

-- Messages keep Gmail's UNREAD mark, so the list can show unread mail in
-- bold. Same check as before, with UNREAD added.
ALTER TABLE mail_messages DROP CONSTRAINT mail_messages_labels_check;
ALTER TABLE mail_messages ADD CONSTRAINT mail_messages_labels_check CHECK (
    array_to_string(labels, ',') ~ ('^((INBOX|STARRED|SENT|DRAFT|IMPORTANT|SPAM|UNREAD'
        || '|CATEGORY_SOCIAL|CATEGORY_UPDATES|CATEGORY_FORUMS|CATEGORY_PROMOTIONS'
        || '|Label_[A-Za-z0-9_-]{1,64})(,|$))*$')
);

-- Gmail's count of unread messages next to each folder's total, read at
-- each import like the total (messagesUnread of users.labels.get).
ALTER TABLE mail_gmail_totals
    ADD COLUMN unread BIGINT NOT NULL DEFAULT 0 CHECK (unread >= 0);
