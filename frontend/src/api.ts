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
  inbox_count: number
  starred_count: number
  sent_count: number
  draft_count: number
}

/** The folders in the mailbox menu, as the Gmail labels the server filters on. */
export type FolderLabel = 'INBOX' | 'STARRED' | 'SENT' | 'DRAFT'

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
  /** Which folders the message is in. */
  labels: FolderLabel[]
}

/** A message with its body. The body is plain text: never render it as HTML. */
export interface MailMessageDetail extends MailMessage {
  body: string
}

export interface MailImportResult {
  imported: number
  accounts: {
    id: string
    email: string
    imported: number
    skipped: number
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

/** Must match the backend's password policy (auth/password.rs). */
export const MIN_PASSWORD_LENGTH = 12
export const MAX_PASSWORD_LENGTH = 128

export interface Registration {
  first_name: string
  last_name: string
  email: string
  password: string
}

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
  /** Creates an email + password account and signs it in. */
  register: (r: Registration) =>
    request<Me>('/auth/register', { method: 'POST', body: JSON.stringify(r) }),
  /** Signs in with email + password. */
  passwordLogin: async (email: string, password: string): Promise<Me> => {
    try {
      return await request<Me>('/auth/password-login', {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      })
    } catch (err) {
      if (err instanceof UnauthorizedError) throw new Error('Invalid email or password.')
      throw err
    }
  },
  /** Changes the password. The server signs out every other session. */
  changePassword: (current_password: string, new_password: string) =>
    request<Me>('/auth/password', {
      method: 'POST',
      body: JSON.stringify({ current_password, new_password }),
    }),
  // JSON body so a cross-site form can't log the user out (CASA 3.1.5).
  logout: () => request<void>('/auth/logout', { method: 'POST', body: '{}' }),
  listMailAccounts: () => request<MailAccount[]>('/mail/accounts'),
  /** Unlinks a mailbox, deletes its imported mail and revokes Google access. */
  disconnectMailAccount: (id: string) =>
    request<void>(`/mail/accounts/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  // JSON body so a cross-site form can't start an import (CASA 3.1.5).
  importMail: () => request<MailImportResult>('/mail/import', { method: 'POST', body: '{}' }),
  /** The newest messages of one mailbox's folder. */
  listMessages: (account: string, label: FolderLabel) =>
    request<MailMessage[]>(`/mail/messages?${new URLSearchParams({ account, label })}`),
  getMessage: (id: string) => request<MailMessageDetail>(`/mail/messages/${encodeURIComponent(id)}`),
}
