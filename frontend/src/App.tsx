import { createEffect, createResource, createSignal, For, Match, onCleanup, Show, Switch } from 'solid-js'
import {
  api,
  downloadAttachment,
  GMAIL_CONNECT_PATH,
  LOGIN_PATH,
  MAX_PASSWORD_LENGTH,
  MIN_PASSWORD_LENGTH,
  UnauthorizedError,
  type FolderLabel,
  type MailAccount,
  type MailAttachment,
  type Me,
} from './api'

/** What a signed-out visitor sees: the welcome page until they pick an action in the header. */
type AuthView = 'home' | 'signin' | 'register'

/** Each signed-out view has its own URL; nginx serves index.html for all of them. */
const VIEW_PATHS: Record<AuthView, string> = {
  home: '/',
  signin: '/auth/signin',
  register: '/auth/register',
}

const viewFromPath = (path: string): AuthView =>
  path === VIEW_PATHS.signin ? 'signin' : path === VIEW_PATHS.register ? 'register' : 'home'

function Welcome() {
  return (
    <section class="welcome">
      <img src="/hadal-icon.png" alt="" width="96" height="96" />
      <h1>Welcome to Hadal</h1>
      <p class="muted">Email in one private space.</p>
    </section>
  )
}

/** Result of a Gmail link, from the `?mail=` flag the server redirects with. */
type LinkResult = 'linked' | 'failed' | null

function SignIn(props: { failed: boolean; onSignedIn: (me: Me) => void; onRegister: () => void }) {
  const [email, setEmail] = createSignal('')
  const [password, setPassword] = createSignal('')
  const [error, setError] = createSignal<string | null>(null)
  const [busy, setBusy] = createSignal(false)

  const submit = async (e: SubmitEvent) => {
    e.preventDefault()
    setError(null)
    setBusy(true)
    try {
      props.onSignedIn(await api.passwordLogin(email(), password()))
    } catch (err) {
      setError((err as Error).message)
      setPassword('')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section class="signin">
      <p>Sign in to see your email.</p>
      <Show when={props.failed}>
        <p class="error" role="alert">Sign-in failed. Please try again.</p>
      </Show>
      <a class="button" href={LOGIN_PATH}>
        Sign in with Google
      </a>

      <p class="muted divider">or</p>

      <form onSubmit={submit} class="auth-form">
        <label>
          Email
          <input
            type="email"
            autocomplete="username"
            value={email()}
            onInput={(e) => setEmail(e.currentTarget.value)}
            maxLength={254}
            required
          />
        </label>
        <label>
          Password
          <input
            type="password"
            autocomplete="current-password"
            value={password()}
            onInput={(e) => setPassword(e.currentTarget.value)}
            maxLength={MAX_PASSWORD_LENGTH}
            required
          />
        </label>
        <Show when={error()}>
          <p class="error" role="alert">{error()}</p>
        </Show>
        <button type="submit" disabled={busy()}>
          {busy() ? 'Signing in…' : 'Sign in'}
        </button>
      </form>

      <p class="muted">
        No account?{' '}
        <button type="button" class="link" onClick={props.onRegister}>
          Create one
        </button>
      </p>
    </section>
  )
}

function Register(props: { onSignedIn: (me: Me) => void; onCancel: () => void }) {
  const [firstName, setFirstName] = createSignal('')
  const [lastName, setLastName] = createSignal('')
  const [email, setEmail] = createSignal('')
  const [password, setPassword] = createSignal('')
  const [confirm, setConfirm] = createSignal('')
  const [error, setError] = createSignal<string | null>(null)
  const [busy, setBusy] = createSignal(false)

  // Checked here for quick feedback; the server enforces the same policy.
  const problem = (): string | null => {
    if (password().length < MIN_PASSWORD_LENGTH)
      return `Password must be at least ${MIN_PASSWORD_LENGTH} characters.`
    if (password() !== confirm()) return 'Passwords do not match.'
    return null
  }

  const submit = async (e: SubmitEvent) => {
    e.preventDefault()
    const p = problem()
    setError(p)
    if (p) return
    setBusy(true)
    try {
      props.onSignedIn(
        await api.register({
          first_name: firstName(),
          last_name: lastName(),
          email: email(),
          password: password(),
        }),
      )
    } catch (err) {
      setError((err as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <section class="signin">
      <h2>Create an account</h2>
      {/* Google sign-in creates the account on first use, so sign-up uses the same flow. */}
      <a class="button" href={LOGIN_PATH}>
        Sign up with Google
      </a>

      <p class="muted divider">or register with email</p>

      <form onSubmit={submit} class="auth-form">
        <div class="row">
          <label>
            First name
            <input
              autocomplete="given-name"
              value={firstName()}
              onInput={(e) => setFirstName(e.currentTarget.value)}
              maxLength={100}
              required
            />
          </label>
          <label>
            Last name
            <input
              autocomplete="family-name"
              value={lastName()}
              onInput={(e) => setLastName(e.currentTarget.value)}
              maxLength={100}
              required
            />
          </label>
        </div>
        <label>
          Email
          <input
            type="email"
            autocomplete="email"
            value={email()}
            onInput={(e) => setEmail(e.currentTarget.value)}
            maxLength={254}
            required
          />
        </label>
        <label>
          Password
          <input
            type="password"
            autocomplete="new-password"
            value={password()}
            onInput={(e) => setPassword(e.currentTarget.value)}
            minLength={MIN_PASSWORD_LENGTH}
            maxLength={MAX_PASSWORD_LENGTH}
            required
          />
          <span class="hint muted">At least {MIN_PASSWORD_LENGTH} characters. A passphrase works well.</span>
        </label>
        <label>
          Confirm password
          <input
            type="password"
            autocomplete="new-password"
            value={confirm()}
            onInput={(e) => setConfirm(e.currentTarget.value)}
            maxLength={MAX_PASSWORD_LENGTH}
            required
          />
        </label>
        <Show when={error()}>
          <p class="error" role="alert">{error()}</p>
        </Show>
        <button type="submit" disabled={busy()}>
          {busy() ? 'Creating account…' : 'Create account'}
        </button>
      </form>
      <p class="muted">
        Already have an account?{' '}
        <button type="button" class="link" onClick={props.onCancel}>
          Sign in
        </button>
      </p>
    </section>
  )
}

function ChangePassword(props: { onDone: (me: Me) => void; onCancel: () => void }) {
  const [current, setCurrent] = createSignal('')
  const [next, setNext] = createSignal('')
  const [confirm, setConfirm] = createSignal('')
  const [error, setError] = createSignal<string | null>(null)
  const [busy, setBusy] = createSignal(false)

  const submit = async (e: SubmitEvent) => {
    e.preventDefault()
    if (next().length < MIN_PASSWORD_LENGTH)
      return setError(`New password must be at least ${MIN_PASSWORD_LENGTH} characters.`)
    if (next() !== confirm()) return setError('New passwords do not match.')
    setError(null)
    setBusy(true)
    try {
      props.onDone(await api.changePassword(current(), next()))
    } catch (err) {
      setError((err as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <section class="signin panel">
      <h2>Change password</h2>
      <form onSubmit={submit} class="auth-form">
        <label>
          Current password
          <input
            type="password"
            autocomplete="current-password"
            value={current()}
            onInput={(e) => setCurrent(e.currentTarget.value)}
            maxLength={MAX_PASSWORD_LENGTH}
            required
          />
        </label>
        <label>
          New password
          <input
            type="password"
            autocomplete="new-password"
            value={next()}
            onInput={(e) => setNext(e.currentTarget.value)}
            minLength={MIN_PASSWORD_LENGTH}
            maxLength={MAX_PASSWORD_LENGTH}
            required
          />
        </label>
        <label>
          Confirm new password
          <input
            type="password"
            autocomplete="new-password"
            value={confirm()}
            onInput={(e) => setConfirm(e.currentTarget.value)}
            maxLength={MAX_PASSWORD_LENGTH}
            required
          />
        </label>
        <Show when={error()}>
          <p class="error" role="alert">{error()}</p>
        </Show>
        <div class="row">
          <button type="submit" disabled={busy()}>
            {busy() ? 'Saving…' : 'Change password'}
          </button>
          <button type="button" class="secondary plain" onClick={props.onCancel}>
            Cancel
          </button>
        </div>
      </form>
    </section>
  )
}

const formatDate = (iso: string) => new Date(iso).toLocaleString()

/** Inbox-list date: the time for today, "Nov 23" for this year, otherwise a short date. */
const listDate = (iso: string) => {
  const d = new Date(iso)
  const now = new Date()
  if (d.toDateString() === now.toDateString()) {
    return d.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })
  }
  if (d.getFullYear() === now.getFullYear()) {
    return d.toLocaleDateString([], { month: 'short', day: 'numeric' })
  }
  return d.toLocaleDateString([], { year: '2-digit', month: 'numeric', day: 'numeric' })
}

/** `Ann Lee <ann@example.com>` → `Ann Lee`; a bare address is shown as it is. */
const senderName = (from: string) => {
  const named = from.match(/^\s*"?([^"<]*?)"?\s*<[^>]*>\s*$/)
  return named?.[1] || from.replace(/[<>]/g, '').trim() || '(unknown sender)'
}

/** The bare address from a From/To header, or the header as it is if it has none. */
const senderAddress = (from: string) => from.match(/<([^>]*)>/)?.[1] || from.trim()

/** "Tue, Nov 24, 9:29 AM": the reading view's date. */
const readerDate = (iso: string) =>
  new Date(iso).toLocaleString([], {
    weekday: 'short',
    month: 'short',
    day: 'numeric',
    year: new Date(iso).getFullYear() === new Date().getFullYear() ? undefined : 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  })

/** 1536 → "1.5 KB". */
const formatSize = (bytes: number) => {
  if (bytes < 1024) return `${bytes} B`
  const units = ['KB', 'MB', 'GB']
  let n = bytes / 1024
  let u = 0
  while (n >= 1024 && u < units.length - 1) {
    n /= 1024
    u++
  }
  return `${n < 10 ? n.toFixed(1) : Math.round(n)} ${units[u]}`
}

/** A short type label for an attachment ("PDF", "PNG") and a colour family for it. */
const fileKind = (a: MailAttachment): { label: string; kind: string } => {
  const ext = a.filename.includes('.') ? a.filename.split('.').pop()!.toLowerCase() : ''
  const label = (ext && ext.length <= 4 ? ext : a.mime_type.split('/').pop() ?? 'file').slice(0, 4).toUpperCase()
  const kind = a.mime_type.startsWith('image/')
    ? 'image'
    : a.mime_type === 'application/pdf' || ext === 'pdf'
      ? 'pdf'
      : /sheet|excel|csv/.test(a.mime_type) || ['xls', 'xlsx', 'csv'].includes(ext)
        ? 'sheet'
        : /word|document|text\//.test(a.mime_type) || ['doc', 'docx', 'txt', 'rtf'].includes(ext)
          ? 'doc'
          : /zip|compressed|tar|gzip/.test(a.mime_type)
            ? 'archive'
            : 'other'
  return { label, kind }
}

/** Simple outline icons for the folder menu (24×24, drawn with the text colour). */
const FolderIcon = (props: { label: FolderLabel }) => (
  <svg class="folder-icon" viewBox="0 0 24 24" aria-hidden="true">
    <Switch>
      <Match when={props.label === 'INBOX'}>
        <path d="M3 13.5 5.6 5h12.8L21 13.5V19H3z" />
        <path d="M3 13.5h5.2l1.3 2.5h5l1.3-2.5H21" />
      </Match>
      <Match when={props.label === 'STARRED'}>
        <path d="m12 3.5 2.6 5.4 5.9.8-4.3 4.1 1 5.8L12 16.9l-5.2 2.7 1-5.8-4.3-4.1 5.9-.8z" />
      </Match>
      <Match when={props.label === 'SENT'}>
        <path d="M3.5 11.5 20.5 4l-7.5 17-2.3-7.2z" />
        <path d="m10.7 13.8 9.8-9.8" />
      </Match>
      <Match when={props.label === 'DRAFT'}>
        <path d="M6 3h8.5L19 7.5V21H6z" />
        <path d="M14.5 3v4.5H19" />
      </Match>
    </Switch>
  </svg>
)

const FOLDERS: { label: FolderLabel; name: string; count: (a: MailAccount) => number }[] = [
  { label: 'INBOX', name: 'Inbox', count: (a) => a.inbox_count },
  { label: 'STARRED', name: 'Starred', count: (a) => a.starred_count },
  { label: 'SENT', name: 'Sent', count: (a) => a.sent_count },
  { label: 'DRAFT', name: 'Drafts', count: (a) => a.draft_count },
]

/** Attachment chips shown under a message row. */
const MAX_ROW_CHIPS = 3

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`

/**
 * Linked Gmail mailboxes and their imported mail, laid out as an inbox:
 * mailboxes on the left, one row per message, and a reading view. Bodies are
 * plain text from the server and are only ever shown as text (CASA 5.1.7).
 */
function Mail(props: { onSignedOut: () => void; linkResult: LinkResult; primaryEmail: string }) {
  const [accounts, { refetch: refetchAccounts }] = createResource(api.listMailAccounts)
  /** The mailbox the user picked; null (or one since disconnected) means the primary one. */
  const [mailbox, setMailbox] = createSignal<string | null>(null)
  const [folder, setFolder] = createSignal<FolderLabel>('INBOX')
  const [openId, setOpenId] = createSignal<string | null>(null)
  const [detail] = createResource(openId, api.getMessage)
  const [importing, setImporting] = createSignal(false)
  const [status, setStatus] = createSignal<string | null>(null)
  const [problems, setProblems] = createSignal<string[]>([])
  const [error, setError] = createSignal<string | null>(null)

  const handle = (err: unknown) => {
    if (err instanceof UnauthorizedError) props.onSignedOut()
    else setError((err as Error).message)
  }

  createEffect(() => {
    if (
      accounts.error instanceof UnauthorizedError ||
      messages.error instanceof UnauthorizedError ||
      detail.error instanceof UnauthorizedError
    ) {
      props.onSignedOut()
    }
  })

  /** The mailbox being shown: the one picked, or the first one. */
  const isPrimary = (account: MailAccount) =>
    account.email.toLowerCase() === props.primaryEmail.toLowerCase()
  /** Mailboxes with the one for the signed-in email (the primary) first. */
  const orderedAccounts = () => {
    const list = accounts() ?? []
    return [...list.filter(isPrimary), ...list.filter((a) => !isPrimary(a))]
  }
  /** The mailbox being shown: the one picked, else the primary, else the first. */
  const selectedAccount = () => {
    const list = orderedAccounts()
    return list.find((a) => a.id === mailbox()) ?? list[0]
  }
  // The open folder of the selected mailbox, fetched from the server.
  const [messages, { refetch: refetchMessages }] = createResource(
    () => {
      const id = selectedAccount()?.id
      return id ? `${id}|${folder()}` : false
    },
    (key) => {
      const [account, label] = key.split('|')
      return api.listMessages(account, label as FolderLabel)
    },
  )
  const visible = () => messages() ?? []
  const folderName = () => FOLDERS.find((f) => f.label === folder())?.name ?? ''
  /** Sent mail and drafts are listed by recipient, the rest by sender. */
  const byRecipient = () => folder() === 'SENT' || folder() === 'DRAFT'

  const showMailbox = (id: string | null) => {
    setMailbox(id)
    setOpenId(null)
  }
  const showFolder = (label: FolderLabel) => {
    setFolder(label)
    setOpenId(null)
  }

  const importAll = async () => {
    setError(null)
    setStatus(null)
    setProblems([])
    setImporting(true)
    try {
      const res = await api.importMail()
      const ok = res.accounts.filter((a) => !a.error).length
      setStatus(
        `Imported ${plural(res.imported, 'new message', 'new messages')} from ${plural(ok, 'mailbox', 'mailboxes')}.`,
      )
      setProblems(res.accounts.filter((a) => a.error).map((a) => `${a.email}: ${a.error}`))
      await Promise.all([refetchAccounts(), refetchMessages()])
    } catch (err) {
      handle(err)
    } finally {
      setImporting(false)
    }
  }

  /** `${messageId}:${index}` of the attachment being downloaded. */
  const [downloading, setDownloading] = createSignal<string | null>(null)
  const download = async (messageId: string, attachment: MailAttachment) => {
    const key = `${messageId}:${attachment.index}`
    if (downloading() === key) return
    setError(null)
    setDownloading(key)
    try {
      await downloadAttachment(messageId, attachment)
    } catch (err) {
      handle(err)
    } finally {
      setDownloading(null)
    }
  }
  const isDownloading = (messageId: string, attachment: MailAttachment) =>
    downloading() === `${messageId}:${attachment.index}`

  const disconnect = async (account: MailAccount) => {
    if (!window.confirm(`Disconnect ${account.email}? Its imported mail will be deleted from Hadal.`)) {
      return
    }
    setError(null)
    try {
      await api.disconnectMailAccount(account.id)
      showMailbox(null)
      await Promise.all([refetchAccounts(), refetchMessages()])
    } catch (err) {
      handle(err)
    }
  }

  return (
    <section class="inbox">
      <aside class="inbox-side">
        <nav class="folders" aria-label="Folders">
          <For each={FOLDERS}>
            {(f) => (
              <button
                class="mailbox folder"
                classList={{ active: folder() === f.label }}
                aria-current={folder() === f.label ? 'true' : undefined}
                onClick={() => showFolder(f.label)}
              >
                <span class="folder-label">
                  <FolderIcon label={f.label} />
                  {f.name}
                </span>
                <Show when={selectedAccount() && f.count(selectedAccount()!) > 0}>
                  <span class="count">{f.count(selectedAccount()!)}</span>
                </Show>
              </button>
            )}
          </For>
        </nav>
        <h2 class="side-heading">Mailboxes</h2>
        <nav class="mailboxes" aria-label="Mailboxes">
          <For each={orderedAccounts()}>
            {(account) => (
              <button
                class="mailbox"
                classList={{ active: selectedAccount()?.id === account.id }}
                aria-current={selectedAccount()?.id === account.id ? 'true' : undefined}
                title={account.email}
                onClick={() => showMailbox(account.id)}
              >
                <span class="mailbox-label">
                  <span class="mailbox-name">{account.email}</span>
                  <Show when={isPrimary(account)}>
                    <span class="primary-tag">Primary</span>
                  </Show>
                </span>
                <span class="count">{account.message_count}</span>
              </button>
            )}
          </For>
          <a class="add-account" href={GMAIL_CONNECT_PATH}>
            {accounts()?.length ? '+ Add another account' : '+ Add an account'}
          </a>
        </nav>
      </aside>

      <div class="inbox-main">
        <div class="inbox-toolbar">
          <Show
            when={openId()}
            fallback={
              <div class="toolbar-group">
                <button
                  class="ghost"
                  onClick={importAll}
                  disabled={importing() || !accounts()?.length}
                  title="Import new mail from every connected mailbox"
                >
                  {importing() ? 'Importing…' : '↻ Import'}
                </button>
                <Show when={selectedAccount()}>
                  {(account) => (
                    <button class="ghost danger" onClick={() => disconnect(account())}>
                      Disconnect
                    </button>
                  )}
                </Show>
              </div>
            }
          >
            <button class="ghost" onClick={() => setOpenId(null)} aria-label="Back to the list">
              ← Back
            </button>
          </Show>
          <Show when={selectedAccount()}>
            {(account) => (
              <span
                class="muted toolbar-status"
                title={account().last_import_at ? formatDate(account().last_import_at!) : undefined}
              >
                {account().last_import_at ? `Imported ${listDate(account().last_import_at!)}` : 'Not imported yet'}
              </span>
            )}
          </Show>
        </div>

        <Show when={props.linkResult === 'linked'}>
          <p class="notice inbox-note" role="status">
            Gmail connected. Use “Import” to fetch its mail.
          </p>
        </Show>
        <Show when={props.linkResult === 'failed'}>
          <p class="error inbox-note" role="alert">
            Gmail wasn't connected. Allow read access to your mail on Google's screen and try again.
          </p>
        </Show>
        <Show when={status()}>
          <p class="notice inbox-note" role="status">{status()}</p>
        </Show>
        <For each={problems()}>{(p) => <p class="error inbox-note" role="alert">{p}</p>}</For>
        <Show when={error()}>
          <p class="error inbox-note" role="alert">{error()}</p>
        </Show>

        <Show when={!accounts.error && !messages.error} fallback={<p class="error inbox-empty">Could not load your mail.</p>}>
          <Show when={!accounts.loading && !messages.loading} fallback={<p class="muted inbox-empty">Loading…</p>}>
            <Show
              when={openId()}
              fallback={
                <Show
                  when={visible().length}
                  fallback={
                    <p class="muted inbox-empty">
                      {!accounts()?.length
                        ? 'No mailboxes connected. Connect a Gmail account to import its newest 100 messages.'
                        : selectedAccount()?.message_count
                          ? `Nothing in ${folderName()}.`
                          : 'No messages yet. Use “Import” to fetch the newest mail from each mailbox.'}
                    </p>
                  }
                >
                  <ul class="message-list">
                    <For each={visible()}>
                      {(m) => (
                        <li>
                          <button class="message-row" onClick={() => setOpenId(m.id)}>
                            <Show
                              when={byRecipient()}
                              fallback={
                                <span class="m-from" title={m.from}>
                                  {senderName(m.from)}
                                </span>
                              }
                            >
                              <span class="m-from" title={m.to}>
                                <Show when={folder() === 'DRAFT'}>
                                  <span class="m-draft">Draft </span>
                                </Show>
                                To: {m.to ? senderName(m.to) : '(no recipient)'}
                              </span>
                            </Show>
                            <span class="m-text">
                              <span class="m-subject">{m.subject || '(no subject)'}</span>
                              <Show when={m.snippet}>
                                <span class="m-snippet"> - {m.snippet}</span>
                              </Show>
                            </span>
                            <span class="m-end">
                              <Show when={m.labels.includes('STARRED')}>
                                <span class="m-star" role="img" aria-label="Starred" title="Starred">
                                  ★
                                </span>
                              </Show>
                              <Show when={m.attachments.length}>
                                <span
                                  class="m-clip"
                                  role="img"
                                  aria-label={plural(m.attachments.length, 'attachment', 'attachments')}
                                  title={plural(m.attachments.length, 'attachment', 'attachments')}
                                >
                                  📎
                                </span>
                              </Show>
                              <time class="m-date" datetime={m.received_at} title={formatDate(m.received_at)}>
                                {listDate(m.received_at)}
                              </time>
                            </span>
                          </button>
                          <Show when={m.attachments.length}>
                            <div class="m-chips">
                              <For each={m.attachments.slice(0, MAX_ROW_CHIPS)}>
                                {(a) => (
                                  <button
                                    class="chip"
                                    classList={{ busy: isDownloading(m.id, a) }}
                                    title={`Download ${a.filename} (${formatSize(a.size)})`}
                                    onClick={() => download(m.id, a)}
                                  >
                                    <span class={`file-badge ${fileKind(a).kind}`}>{fileKind(a).label}</span>
                                    <span class="chip-name">{a.filename}</span>
                                  </button>
                                )}
                              </For>
                              <Show when={m.attachments.length > MAX_ROW_CHIPS}>
                                <button class="chip more" onClick={() => setOpenId(m.id)}>
                                  +{m.attachments.length - MAX_ROW_CHIPS}
                                </button>
                              </Show>
                            </div>
                          </Show>
                        </li>
                      )}
                    </For>
                  </ul>
                </Show>
              }
            >
              <Show when={!detail.error} fallback={<p class="error inbox-empty">Could not open this message.</p>}>
                <Show
                  when={!detail.loading && detail()?.id === openId() ? detail() : undefined}
                  fallback={<p class="muted inbox-empty">Loading…</p>}
                >
                  {(d) => (
                    <article class="reader">
                      <h2>{d().subject || '(no subject)'}</h2>
                      <div class="reader-meta">
                        <div class="reader-people">
                          <strong>{senderName(d().from)}</strong>{' '}
                          <span class="muted">&lt;{senderAddress(d().from)}&gt;</span>
                          <div class="muted">to {d().to || '(none)'}</div>
                        </div>
                        <time class="muted" datetime={d().received_at} title={formatDate(d().received_at)}>
                          {readerDate(d().received_at)}
                        </time>
                      </div>
                      <pre>{d().body || '(This message has no text.)'}</pre>
                      <Show when={d().attachments.length}>
                        <section class="attachments" aria-label="Attachments">
                          <h3>{plural(d().attachments.length, 'attachment', 'attachments')}</h3>
                          <ul>
                            <For each={d().attachments}>
                              {(a) => (
                                <li class="attachment-card">
                                  <span class={`file-badge large ${fileKind(a).kind}`}>{fileKind(a).label}</span>
                                  <span class="attachment-info">
                                    <span class="attachment-name" title={a.filename}>
                                      {a.filename}
                                    </span>
                                    <span class="muted">{formatSize(a.size)}</span>
                                  </span>
                                  <button
                                    class="ghost"
                                    disabled={isDownloading(d().id, a)}
                                    onClick={() => download(d().id, a)}
                                    aria-label={`Download ${a.filename}`}
                                  >
                                    {isDownloading(d().id, a) ? 'Downloading…' : '↓ Download'}
                                  </button>
                                </li>
                              )}
                            </For>
                          </ul>
                        </section>
                      </Show>
                    </article>
                  )}
                </Show>
              </Show>
            </Show>
          </Show>
        </Show>
      </div>
    </section>
  )
}

function App() {
  const [me, { mutate }] = createResource<Me | null>(api.me)
  const query = new URLSearchParams(window.location.search)
  // A failed Google sign-in comes back to /?login=failed; show the sign-in page with the error.
  const loginFailed = query.get('login') === 'failed'
  const [view, setView] = createSignal<AuthView>(loginFailed ? 'signin' : viewFromPath(window.location.pathname))
  const [changing, setChanging] = createSignal(false)
  const [notice, setNotice] = createSignal<string | null>(null)
  const mailFlag = query.get('mail')
  const linkResult: LinkResult = mailFlag === 'linked' || mailFlag === 'failed' ? mailFlag : null
  if (loginFailed || mailFlag !== null) {
    // Drop the flag so a reload doesn't show the message again.
    window.history.replaceState(null, '', VIEW_PATHS[view()])
  }

  /** Show a view and put its URL in the address bar (a new history entry unless `replace`). */
  const navigate = (next: AuthView, replace = false) => {
    if (window.location.pathname !== VIEW_PATHS[next]) {
      if (replace) window.history.replaceState(null, '', VIEW_PATHS[next])
      else window.history.pushState(null, '', VIEW_PATHS[next])
    }
    setView(next)
  }

  // Back/forward buttons.
  const onPopState = () => setView(viewFromPath(window.location.pathname))
  window.addEventListener('popstate', onPopState)
  onCleanup(() => window.removeEventListener('popstate', onPopState))

  // Signed in on /auth/signin or /auth/register: those pages don't apply, go home.
  createEffect(() => {
    if (me() && view() !== 'home') navigate('home', true)
  })

  /** Click handler for in-app links; leaves new-tab/modified clicks to the browser. */
  const linkTo = (next: AuthView) => (e: MouseEvent) => {
    if (e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return
    e.preventDefault()
    navigate(next)
  }

  const signOut = async () => {
    try {
      await api.logout()
    } finally {
      mutate(null)
      navigate('home')
      setChanging(false)
      setNotice(null)
    }
  }

  return (
    <>
      <header class="site-header">
        <div class="site-header-inner" classList={{ wide: !!me() }}>
        <a class="brand" href={VIEW_PATHS.home} onClick={linkTo('home')} aria-label="Hadal home">
          <img class="brand-mark" src="/hadal-icon.png" alt="" width="32" height="32" />
          Hadal
        </a>
        <Show
          when={me()}
          fallback={
            <Show when={!me.loading && !me.error}>
              <nav class="auth-nav" aria-label="Account">
                <a
                  href={VIEW_PATHS.signin}
                  aria-current={view() === 'signin' ? 'page' : undefined}
                  onClick={linkTo('signin')}
                >
                  Sign in
                </a>
                <a
                  class="primary"
                  href={VIEW_PATHS.register}
                  aria-current={view() === 'register' ? 'page' : undefined}
                  onClick={linkTo('register')}
                >
                  Register
                </a>
              </nav>
            </Show>
          }
        >
          {(user) => (
            <div class="user">
              <span>
                <Show when={[user().first_name, user().last_name].filter(Boolean).join(' ')}>
                  {(name) => <strong>{name()} </strong>}
                </Show>
                <span class="muted">{user().email}</span>
              </span>
              <Show when={user().has_password}>
                <button class="secondary plain" onClick={() => setChanging(!changing())}>
                  Change password
                </button>
              </Show>
              <button class="secondary" onClick={signOut}>
                Sign out
              </button>
            </div>
          )}
        </Show>
        </div>
      </header>

      <main classList={{ wide: !!me() }}>
      <Show when={!me.error} fallback={<p class="error">Could not reach the server.</p>}>
        <Show when={!me.loading} fallback={<p class="muted">Loading…</p>}>
          <Show
            when={me()}
            fallback={
              <Switch>
                <Match when={view() === 'signin'}>
                  <SignIn failed={loginFailed} onSignedIn={mutate} onRegister={() => navigate('register')} />
                </Match>
                <Match when={view() === 'register'}>
                  <Register onSignedIn={mutate} onCancel={() => navigate('signin')} />
                </Match>
                <Match when={view() === 'home'}>
                  <Welcome />
                </Match>
              </Switch>
            }
          >
            <Show when={notice()}>
              <p class="notice" role="status">{notice()}</p>
            </Show>
            <Show when={changing()}>
              <ChangePassword
                onCancel={() => setChanging(false)}
                onDone={(m) => {
                  mutate(m)
                  setChanging(false)
                  setNotice('Password changed. You were signed out everywhere else.')
                }}
              />
            </Show>
            <Mail onSignedOut={() => mutate(null)} linkResult={linkResult} primaryEmail={me()?.email ?? ''} />
          </Show>
        </Show>
      </Show>
      </main>
    </>
  )
}

export default App
