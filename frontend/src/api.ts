export interface Me {
  email: string
  /** Null for Google accounts that don't share a name. */
  first_name: string | null
  last_name: string | null
  /** False for Google accounts, which have no password here. */
  has_password: boolean
}

/** A linked Gmail mailbox. */
export interface MailAccount {
  id: string
  email: string
  created_at: string
  last_import_at: string | null
  message_count: number
  /** Messages per label ID (`INBOX`, `Label_12`, …), plus `ALL` for everything but spam. */
  folder_counts: Record<string, number>
  /**
   * Gmail's own count per label ID, plus `ALL` (everything but spam and
   * trash), read at each import: the mailbox's real size, mail not imported
   * yet included. Empty until the first import has read them.
   */
  gmail_counts: Record<string, number>
  /** Gmail's count of unread messages, for the same keys. */
  gmail_unread: Record<string, number>
  /** The mailbox's own Gmail labels. */
  labels: MailLabel[]
}

/** One of the user's own Gmail labels. */
export interface MailLabel {
  id: string
  name: string
  /** `#rrggbb`, if Gmail gives it a colour. */
  color: string | null
}

/**
 * What the message list shows: `ALL` (everything but spam), a Gmail system
 * label such as `INBOX` or `CATEGORY_UPDATES`, or a user label ID.
 */
export type FolderLabel = string

/** A file attached to an imported message. It is fetched from Gmail only when downloaded. */
export interface MailAttachment {
  /** Its position in the message; how the download asks for it. */
  index: number
  filename: string
  mime_type: string
  /** Bytes, as Gmail reports it. */
  size: number
}

/** An imported message, without its body. */
export interface MailMessage {
  id: string
  account_id: string
  account_email: string
  received_at: string
  from: string
  to: string
  subject: string
  snippet: string
  attachments: MailAttachment[]
  /** Which folders the message is in, plus `UNREAD` while it is unread in Gmail. */
  labels: FolderLabel[]
}

/** A message with its body. The body is plain text: never render it as HTML. */
export interface MailMessageDetail extends MailMessage {
  body: string
}

/** Messages per page of the list (the backend's `mail::PAGE_SIZE`). */
export const PAGE_SIZE = 50

export interface MailImportResult {
  imported: number
  accounts: {
    id: string
    email: string
    imported: number
    skipped: number
    /** Older mail is still to come: importing again continues. */
    remaining: boolean
    /** A user-facing reason this mailbox failed, or null. */
    error: string | null
  }[]
}

/** The session is missing or expired: the user has to sign in again. */
export class UnauthorizedError extends Error {}

// Auth is the HttpOnly session cookie, which the browser attaches to these
// same-origin requests by itself. No credentials are read or stored here
// (CASA 6.6.1).
async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`/api${path}`, {
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    ...init,
  })
  if (res.status === 401) {
    throw new UnauthorizedError('Please sign in again.')
  }
  if (!res.ok) {
    const data = await res.json().catch(() => ({}))
    throw new Error(data.error ?? `Request failed (${res.status})`)
  }
  return (res.status === 204 ? undefined : await res.json()) as T
}

/**
 * Downloads a message attachment and hands it to the browser as a file to
 * save. Fetched rather than linked so a failure can be shown in the page; the
 * server always sends it as an opaque download, never as a page to render.
 */
export async function downloadAttachment(messageId: string, attachment: MailAttachment): Promise<void> {
  const res = await fetch(
    `/api/mail/messages/${encodeURIComponent(messageId)}/attachments/${attachment.index}`,
    { credentials: 'same-origin' },
  )
  if (res.status === 401) {
    throw new UnauthorizedError('Please sign in again.')
  }
  if (!res.ok) {
    const data = await res.json().catch(() => ({}))
    throw new Error(data.error ?? `Download failed (${res.status})`)
  }
  const url = URL.createObjectURL(await res.blob())
  try {
    const link = document.createElement('a')
    link.href = url
    link.download = attachment.filename
    link.click()
  } finally {
    // Give the browser a moment to start saving before the URL goes away.
    setTimeout(() => URL.revokeObjectURL(url), 10_000)
  }
}

/** Starts Google sign-in. A plain link: the server redirects to Google. */
export const LOGIN_PATH = '/api/auth/login'

/** Links a Gmail mailbox. A plain link: the server redirects to Google. */
export const GMAIL_CONNECT_PATH = '/api/auth/gmail/connect'

export const api = {
  /** The signed-in user, or `null` when signed out. */
  me: async (): Promise<Me | null> => {
    try {
      return await request<Me>('/auth/me')
    } catch (err) {
      if (err instanceof UnauthorizedError) return null
      throw err
    }
  },
  /** Renames the signed-in user. From then on Google sign-in keeps this name. */
  updateProfile: (first_name: string, last_name: string) =>
    request<Me>('/auth/profile', {
      method: 'POST',
      body: JSON.stringify({ first_name, last_name }),
    }),
  // JSON body so a cross-site form can't log the user out (CASA 3.1.5).
  logout: () => request<void>('/auth/logout', { method: 'POST', body: '{}' }),
  listMailAccounts: () => request<MailAccount[]>('/mail/accounts'),
  /** Unlinks a mailbox, deletes its imported mail and revokes Google access. */
  disconnectMailAccount: (id: string) =>
    request<void>(`/mail/accounts/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  // JSON body so a cross-site form can't start an import (CASA 3.1.5).
  importMail: () => request<MailImportResult>('/mail/import', { method: 'POST', body: '{}' }),
  /** One page (`PAGE_SIZE`, newest first, counted from 0) of a mailbox's folder. */
  listMessages: (account: string, label: FolderLabel, page: number) =>
    request<MailMessage[]>(
      `/mail/messages?${new URLSearchParams({ account, label, page: String(page) })}`,
    ),
  getMessage: (id: string) => request<MailMessageDetail>(`/mail/messages/${encodeURIComponent(id)}`),
}
