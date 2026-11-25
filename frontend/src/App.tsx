import { createEffect, createResource, createSignal, For, Match, onCleanup, Show, Switch } from 'solid-js'
import {
  api,
  downloadAttachment,
  GMAIL_CONNECT_PATH,
  LOGIN_PATH,
  PAGE_SIZE,
  UnauthorizedError,
  watchMail,
  type FolderLabel,
  type MailAccount,
  type MailAttachment,
  type Me,
} from './api'

/**
 * The page being shown. Signed out: the welcome page until they pick an
 * action in the header. Signed in: the mail (`home`) or Settings.
 */
type AuthView = 'home' | 'signin' | 'register' | 'settings'

/** Each view has its own URL; nginx serves index.html for all of them. */
const VIEW_PATHS: Record<AuthView, string> = {
  home: '/',
  signin: '/auth/signin',
  register: '/auth/register',
  settings: '/settings',
}

const viewFromPath = (path: string): AuthView =>
  (Object.keys(VIEW_PATHS) as AuthView[]).find((v) => VIEW_PATHS[v] === path) ?? 'home'

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

/** Sign-in: Google only. (Email + password accounts are switched off.) */
function SignIn(props: { failed: boolean; onRegister: () => void }) {
  return (
    <section class="signin">
      <h2>Sign in</h2>
      <p class="muted">Sign in with your Google account to see your email.</p>
      <Show when={props.failed}>
        <p class="error" role="alert">Sign-in failed. Please try again.</p>
      </Show>
      <a class="button" href={LOGIN_PATH}>
        Sign in with Google
      </a>
      <p class="muted">
        New to Hadal?{' '}
        <button type="button" class="link" onClick={props.onRegister}>
          Create an account
        </button>
      </p>
    </section>
  )
}

/** Sign-up: Google only. Google sign-in creates the account on first use. */
function Register(props: { onCancel: () => void }) {
  return (
    <section class="signin">
      <h2>Create an account</h2>
      <p class="muted">Hadal accounts use Google sign-in. Your account is created the first time you sign in.</p>
      <a class="button" href={LOGIN_PATH}>
        Sign up with Google
      </a>
      <p class="muted">
        Already have an account?{' '}
        <button type="button" class="link" onClick={props.onCancel}>
          Sign in
        </button>
      </p>
    </section>
  )
}

/** Settings: the user's name, connected accounts, and sign out. */
function Settings(props: {
  me: Me
  onUpdated: (me: Me) => void
  onSignedOut: () => void
  /** Ends this session (the Sign out button). */
  onSignOut: () => void
  backLink: (e: MouseEvent) => void
}) {
  const [first, setFirst] = createSignal(props.me.first_name ?? '')
  const [last, setLast] = createSignal(props.me.last_name ?? '')
  const [error, setError] = createSignal<string | null>(null)
  const [saved, setSaved] = createSignal(false)
  const [busy, setBusy] = createSignal(false)
  const [accounts, { refetch: refetchAccounts }] = createResource(api.listMailAccounts)
  const [accountError, setAccountError] = createSignal<string | null>(null)
  createEffect(() => {
    if (accounts.error instanceof UnauthorizedError) props.onSignedOut()
  })
  const disconnect = async (account: MailAccount) => {
    if (!window.confirm(`Disconnect ${account.email}? Its imported mail will be deleted from Hadal.`)) {
      return
    }
    setAccountError(null)
    try {
      await api.disconnectMailAccount(account.id)
      await refetchAccounts()
    } catch (err) {
      if (err instanceof UnauthorizedError) props.onSignedOut()
      else setAccountError((err as Error).message)
    }
  }
  const unchanged = () =>
    first().trim() === (props.me.first_name ?? '') && last().trim() === (props.me.last_name ?? '')

  const saveProfile = async (e: SubmitEvent) => {
    e.preventDefault()
    setError(null)
    setSaved(false)
    setBusy(true)
    try {
      const me = await api.updateProfile(first(), last())
      props.onUpdated(me)
      setFirst(me.first_name ?? '')
      setLast(me.last_name ?? '')
      setSaved(true)
    } catch (err) {
      if (err instanceof UnauthorizedError) props.onSignedOut()
      else setError((err as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div class="settings">
      <a class="back-link" href="/" onClick={props.backLink}>
        ← Back to mail
      </a>
      <h1>Settings</h1>

      <section class="panel settings-card" aria-labelledby="profile-heading">
        <h2 id="profile-heading">Profile</h2>
        <form onSubmit={saveProfile} class="auth-form">
          <div class="row">
            <label>
              First name
              <input
                autocomplete="given-name"
                value={first()}
                onInput={(e) => {
                  setFirst(e.currentTarget.value)
                  setSaved(false)
                }}
                maxLength={100}
                required
              />
            </label>
            <label>
              Last name
              <input
                autocomplete="family-name"
                value={last()}
                onInput={(e) => {
                  setLast(e.currentTarget.value)
                  setSaved(false)
                }}
                maxLength={100}
                required
              />
            </label>
          </div>
          <label>
            Email
            <input type="email" value={props.me.email} disabled />
            <span class="hint muted">The email you sign in with. It can't be changed here.</span>
          </label>
          <Show when={error()}>
            <p class="error" role="alert">{error()}</p>
          </Show>
          <Show when={saved()}>
            <p class="notice" role="status">Profile saved.</p>
          </Show>
          <button type="submit" disabled={busy() || unchanged()}>
            {busy() ? 'Saving…' : 'Save'}
          </button>
        </form>
      </section>

      <section class="panel settings-card" aria-labelledby="accounts-heading">
        <h2 id="accounts-heading">Connected accounts</h2>
        <Show when={!accounts.error} fallback={<p class="error">Could not load your connected accounts.</p>}>
          <Show when={!accounts.loading} fallback={<p class="muted">Loading…</p>}>
            <Show
              when={accounts()?.length}
              fallback={<p class="muted">No Gmail accounts connected yet.</p>}
            >
              <ul class="connected-accounts">
                <For each={accounts()}>
                  {(account) => (
                    <li>
                      <span class="connected-info">
                        <span class="connected-email">{account.email}</span>
                        <span class="muted">
                          {plural(mailboxSize(account), 'message', 'messages')}
                          {' · connected '}
                          {readerDate(account.created_at)}
                          {account.last_import_at
                            ? ` · imported ${listDate(account.last_import_at)}`
                            : ' · not imported yet'}
                        </span>
                      </span>
                      <Show
                        when={account.email.toLowerCase() !== props.me.email.toLowerCase()}
                        fallback={
                          <span class="muted sign-in-account" title="The account you sign in with can't be disconnected">
                            Sign-in account
                          </span>
                        }
                      >
                        <button
                          class="ghost danger"
                          onClick={() => disconnect(account)}
                          aria-label={`Disconnect ${account.email}`}
                        >
                          Disconnect
                        </button>
                      </Show>
                    </li>
                  )}
                </For>
              </ul>
            </Show>
            <Show when={accountError()}>
              <p class="error" role="alert">{accountError()}</p>
            </Show>
            <a class="add-account" href={GMAIL_CONNECT_PATH}>
              {accounts()?.length ? '+ Add another account' : '+ Add an account'}
            </a>
          </Show>
        </Show>
      </section>

      <section class="panel settings-card" aria-labelledby="signout-heading">
        <h2 id="signout-heading">Sign out</h2>
        <p class="muted">Sign out of Hadal on this device.</p>
        <button class="secondary sign-out" onClick={props.onSignOut}>
          Sign out
        </button>
      </section>
    </div>
  )
}

const formatDate = (iso: string) => new Date(iso).toLocaleString()

/** A sidebar count: unread in bold, when there is any, then the total. */
/** How long to wait before importing again when the mailbox is busy. */
const BUSY_RETRY_MS = 20_000
/** How long to wait after an import round that Gmail slowed to nothing. */
const SLOW_DOWN_MS = 10_000
/** How long a burst of live changes is gathered before the list reloads once. */
const LIVE_RELOAD_MS = 1_000

/**
 * The number next to a folder, as Gmail's sidebar shows it: unread
 * conversations, in bold, and nothing when none are unread. Drafts show how
 * many there are; Sent, Starred, Important and All mail show nothing.
 */
function FolderCount(props: { label: FolderLabel; counts: Record<string, number>; unread: Record<string, number> }) {
  const shown = () => {
    if (props.label === 'DRAFT') return { n: props.counts.DRAFT ?? 0, unread: false }
    if (['SENT', 'STARRED', 'IMPORTANT', 'ALL'].includes(props.label)) return { n: 0, unread: false }
    return { n: props.unread[props.label] ?? 0, unread: true }
  }
  return (
    <Show when={shown().n > 0}>
      <span
        class="count"
        classList={{ 'unread-count': shown().unread }}
        title={shown().unread ? `${shown().n.toLocaleString()} unread` : undefined}
      >
        {shown().n.toLocaleString()}
      </span>
    </Show>
  )
}

/** A mailbox's size in Gmail (all but spam and trash); until the first
 * import has read it, the messages imported so far. */
const mailboxSize = (account: MailAccount) => account.gmail_counts.ALL ?? account.message_count

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
      <Match when={props.label === 'IMPORTANT'}>
        <path d="M4 6h11l5 6-5 6H4l4-6z" />
      </Match>
      <Match when={props.label === 'ALL'}>
        <path d="M4 8h16v11H4z" />
        <path d="M6 5h12M8 2.5h8" />
      </Match>
      <Match when={props.label === 'SPAM'}>
        <path d="M8.3 3h7.4L21 8.3v7.4L15.7 21H8.3L3 15.7V8.3z" />
        <path d="M12 7.5v5.5M12 16.5v.01" />
      </Match>
      <Match when={props.label === 'CATEGORY_SOCIAL'}>
        <circle cx="9" cy="8" r="3.2" />
        <path d="M3 19c.6-3.4 3-5 6-5s5.4 1.6 6 5" />
        <path d="M15.5 4.9a3.2 3.2 0 0 1 0 6.2M17.5 14.3c1.8.6 3 2.1 3.5 4.7" />
      </Match>
      <Match when={props.label === 'CATEGORY_UPDATES'}>
        <circle cx="12" cy="12" r="9" />
        <path d="M12 11v6M12 7.5v.01" />
      </Match>
      <Match when={props.label === 'CATEGORY_FORUMS'}>
        <path d="M3 4h13v9H8l-5 4z" />
        <path d="M16 8h5v12l-4-3h-7v-4" />
      </Match>
      <Match when={props.label === 'CATEGORY_PROMOTIONS'}>
        <path d="M3 12.6V4h8.6L21 13.4 13.4 21z" />
        <path d="M7.5 7.5v.01" />
      </Match>
    </Switch>
  </svg>
)

/** A user label's icon: a tag in the label's own colour. */
const LabelIcon = (props: { color: string | null }) => (
  <svg class="folder-icon label-icon" viewBox="0 0 24 24" aria-hidden="true">
    <path d="M3 6.5h12.5L21 12l-5.5 5.5H3z" style={{ fill: props.color ?? 'var(--muted)' }} />
  </svg>
)

type Folder = { label: FolderLabel; name: string }

const FOLDERS: Folder[] = [
  { label: 'INBOX', name: 'Inbox' },
  { label: 'STARRED', name: 'Starred' },
  { label: 'SENT', name: 'Sent' },
  { label: 'DRAFT', name: 'Drafts' },
]

/** Shown under "More". (Gmail's API has no Scheduled, Snoozed or Purchases.) */
const MORE_FOLDERS: Folder[] = [
  { label: 'IMPORTANT', name: 'Important' },
  { label: 'ALL', name: 'All mail' },
  { label: 'SPAM', name: 'Spam' },
  { label: 'CATEGORY_SOCIAL', name: 'Social' },
  { label: 'CATEGORY_UPDATES', name: 'Updates' },
  { label: 'CATEGORY_FORUMS', name: 'Forums' },
  { label: 'CATEGORY_PROMOTIONS', name: 'Promotions' },
]

/** Attachment chips shown under a message row. */
const MAX_ROW_CHIPS = 3

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`

/**
 * Linked Gmail mailboxes and their imported mail, laid out as an inbox:
 * mailboxes on the left, one row per message, and a reading view. Bodies are
 * plain text from the server and are only ever shown as text (CASA 5.1.7).
 */
function Mail(props: {
  onSignedOut: () => void
  linkResult: LinkResult
  primaryEmail: string
  /** Opens Settings (an in-app link). */
  settingsLink: (e: MouseEvent) => void
}) {
  const [accounts, { refetch: refetchAccounts }] = createResource(api.listMailAccounts)
  /** The mailbox the user picked; null (or one since disconnected) means the primary one. */
  const [mailbox, setMailbox] = createSignal<string | null>(null)
  const [folder, setFolder] = createSignal<FolderLabel>('INBOX')
  const [openId, setOpenId] = createSignal<string | null>(null)
  const [detail] = createResource(openId, api.getMessage)
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
  /** The selected mailbox if it can be disconnected (it isn't the sign-in one). */
  const disconnectable = () => {
    const account = selectedAccount()
    return account && !isPrimary(account) ? account : undefined
  }
  /** Page of the list being shown, counted from 0; back to 0 on a new folder. */
  const [page, setPage] = createSignal(0)
  // The shown page of the selected mailbox's open folder, fetched from the server.
  const [messages, { refetch: refetchMessages }] = createResource(
    () => {
      const id = selectedAccount()?.id
      return id ? `${id}|${folder()}|${page()}` : false
    },
    (key) => {
      const [account, label, n] = key.split('|')
      return api.listMessages(account, label as FolderLabel, Number(n))
    },
  )
  const visible = () => messages() ?? []
  const folderName = () =>
    [...FOLDERS, ...MORE_FOLDERS].find((f) => f.label === folder())?.name ??
    selectedAccount()?.labels.find((l) => l.id === folder())?.name ??
    ''
  /** How many messages a folder holds in Gmail: shown, so it doesn't climb
   * while the import catches up. Before Gmail's counts arrive, what's here. */
  const countOf = (label: FolderLabel) => {
    const account = selectedAccount()
    return account?.gmail_counts[label] ?? account?.folder_counts[label] ?? 0
  }
  /** How many of them are imported, so far: as far as the pages go. */
  const importedOf = (label: FolderLabel) => selectedAccount()?.folder_counts[label] ?? 0
  /** "More" is open when asked, or when one of its folders is showing. */
  const [moreOpen, setMoreOpen] = createSignal(false)
  const showMore = () => moreOpen() || MORE_FOLDERS.some((f) => f.label === folder())
  const userLabel = (id: string) => selectedAccount()?.labels.find((l) => l.id === id)
  /** Sent mail and drafts are listed by recipient, the rest by sender. */
  const byRecipient = () => folder() === 'SENT' || folder() === 'DRAFT'

  const showMailbox = (id: string | null) => {
    setMailbox(id)
    setOpenId(null)
    setPage(0)
    // A user label belongs to one mailbox; another one starts at its Inbox.
    if (folder().startsWith('Label_')) setFolder('INBOX')
  }
  const showFolder = (label: FolderLabel) => {
    setFolder(label)
    setOpenId(null)
    setPage(0)
  }

  /** Messages in the open folder, for "1–50 of N" and the page buttons. */
  const total = () => countOf(folder())
  const firstShown = () => page() * PAGE_SIZE + 1
  const lastShown = () => page() * PAGE_SIZE + visible().length
  // Up to the imported mail: Gmail's count may be ahead of it for a while.
  const hasNext = () => (page() + 1) * PAGE_SIZE < importedOf(folder())
  /** Page buttons only when the folder doesn't fit on one page. */
  const paged = () => page() > 0 || total() > PAGE_SIZE
  const turnPage = (to: number) => {
    setPage(to)
    document.querySelector('.inbox-main')?.scrollIntoView({ block: 'nearest' })
  }

  /** True while an import refreshes the list: the list stays up meanwhile. */
  const [refreshing, setRefreshing] = createSignal(false)
  let stopped = false
  onCleanup(() => {
    stopped = true
  })

  /**
   * Imports every connected account in full. Each request imports what fits
   * in its time and the next one continues, so this repeats until no account
   * has older mail left, one fails, or the user leaves. Runs by itself once
   * the accounts have loaded; only failures are shown.
   */
  const importAll = async () => {
    setError(null)
    setProblems([])
    try {
      while (!stopped) {
        let res
        try {
          res = await api.importMail()
        } catch (err) {
          // Another tab is importing, or an import cut short (the server
          // restarted) still holds the mailbox for up to a minute: wait,
          // then try again rather than give up.
          // Likewise when the server asks to slow down (many reloads in a
          // row): the import still has to happen.
          if (
            err instanceof Error &&
            (err.message === 'an import is already running' || err.message === 'too many requests')
          ) {
            await new Promise((resolve) => setTimeout(resolve, BUSY_RETRY_MS))
            continue
          }
          throw err
        }
        setProblems(res.accounts.filter((a) => a.error).map((a) => `${a.email}: ${a.error}`))
        // Always: Gmail's counts and read marks may change without new mail.
        if (!stopped) {
          setRefreshing(true)
          try {
            await Promise.all([refetchAccounts(), refetchMessages()])
          } finally {
            setRefreshing(false)
          }
        }
        if (!res.accounts.some((a) => a.remaining && !a.error)) break
        // Mail is left but this round got none: Gmail asked to slow down.
        // Give its per-user quota a moment before the next round.
        if (res.imported === 0) await new Promise((resolve) => setTimeout(resolve, SLOW_DOWN_MS))
      }
    } catch (err) {
      handle(err)
    }
  }

  // New mail as it arrives: Gmail tells the server, the server tells this
  // page, and the page reloads the list. Changes close together reload once.
  let reloadTimer: ReturnType<typeof setTimeout> | undefined
  const reloadSoon = () => {
    if (reloadTimer !== undefined) return
    reloadTimer = setTimeout(async () => {
      reloadTimer = undefined
      if (stopped) return
      try {
        await Promise.all([refetchAccounts(), refetchMessages()])
      } catch (err) {
        handle(err)
      }
    }, LIVE_RELOAD_MS)
  }
  const stopWatching = watchMail(reloadSoon, () => {
    // The stream can't reconnect: usually the session ended. Check.
    api.me().then((me) => me ?? props.onSignedOut(), () => {})
  })
  onCleanup(() => {
    stopWatching()
    if (reloadTimer !== undefined) clearTimeout(reloadTimer)
  })

  // Import automatically once per page load, as soon as there is an account.
  let autoImported = false
  createEffect(() => {
    if (!autoImported && accounts()?.length) {
      autoImported = true
      void importAll()
    }
  })

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
        <div class="side-scroll">
          <div class="side-block">
            <h2 class="side-heading">Accounts</h2>
            <nav class="mailboxes" aria-label="Accounts">
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
                    </span>
                    {/* Like Gmail's account list: unread in the Inbox. */}
                    <FolderCount label="INBOX" counts={account.gmail_counts} unread={account.gmail_unread} />
                  </button>
                )}
              </For>
              <a class="add-account" href={GMAIL_CONNECT_PATH}>
                {accounts()?.length ? '+ Add another account' : '+ Add an account'}
              </a>
            </nav>
          </div>
          <nav class="folders" aria-label="Folders">
            <For each={showMore() ? [...FOLDERS, ...MORE_FOLDERS] : FOLDERS}>
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
                  <FolderCount
                    label={f.label}
                    counts={selectedAccount()?.gmail_counts ?? {}}
                    unread={selectedAccount()?.gmail_unread ?? {}}
                  />
                </button>
              )}
            </For>
            <button
              class="mailbox folder more-toggle"
              aria-expanded={showMore()}
              onClick={() => setMoreOpen(!showMore())}
              disabled={MORE_FOLDERS.some((f) => f.label === folder())}
            >
              <span class="folder-label">
                <svg class="folder-icon" viewBox="0 0 24 24" aria-hidden="true">
                  <path d={showMore() ? 'm6 15 6-6 6 6' : 'm6 9 6 6 6-6'} />
                </svg>
                {showMore() ? 'Less' : 'More'}
              </span>
            </button>
          </nav>
          <Show when={selectedAccount()?.labels.length}>
            <h2 class="side-heading labels-heading">Labels</h2>
            <nav class="folders labels" aria-label="Labels">
              <For each={selectedAccount()?.labels}>
                {(l) => (
                  <button
                    class="mailbox folder"
                    classList={{ active: folder() === l.id }}
                    aria-current={folder() === l.id ? 'true' : undefined}
                    title={l.name}
                    onClick={() => showFolder(l.id)}
                  >
                    <span class="folder-label">
                      <LabelIcon color={l.color} />
                      <span class="mailbox-name">{l.name}</span>
                    </span>
                    <FolderCount
                      label={l.id}
                      counts={selectedAccount()?.gmail_counts ?? {}}
                      unread={selectedAccount()?.gmail_unread ?? {}}
                    />
                  </button>
                )}
              </For>
            </nav>
          </Show>
        </div>
        <a class="side-settings" href="/settings" onClick={props.settingsLink}>
          <svg class="folder-icon" viewBox="0 0 24 24" aria-hidden="true">
            <circle cx="12" cy="12" r="3" />
            <path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z" />
          </svg>
          Settings
        </a>
      </aside>

      <div class="inbox-main">
        {/* Only when there's something in it: Back, Disconnect for a
            non-primary mailbox, or the page buttons. */}
        <Show when={openId() || disconnectable() || paged()}>
          <div class="inbox-toolbar">
            <Show
              when={openId()}
              fallback={
                <>
                  <div class="toolbar-group">
                    <Show when={disconnectable()}>
                      {(account) => (
                        <button class="ghost danger" onClick={() => disconnect(account())}>
                          Disconnect
                        </button>
                      )}
                    </Show>
                  </div>
                  <Show when={paged()}>
                    <nav class="toolbar-group pager" aria-label="Pages">
                      <span class="muted toolbar-status">
                        {visible().length
                          ? `${firstShown()}–${lastShown()} of ${total().toLocaleString()}`
                          : `${total().toLocaleString()} messages`}
                      </span>
                      <button
                        class="ghost"
                        onClick={() => turnPage(page() - 1)}
                        disabled={page() === 0}
                        aria-label="Newer messages"
                        title="Newer"
                      >
                        ‹ Previous
                      </button>
                      <button
                        class="ghost"
                        onClick={() => turnPage(page() + 1)}
                        disabled={!hasNext()}
                        aria-label="Older messages"
                        title="Older"
                      >
                        Next ›
                      </button>
                    </nav>
                  </Show>
                </>
              }
            >
              <button class="ghost" onClick={() => setOpenId(null)} aria-label="Back to the list">
                ← Back
              </button>
            </Show>
          </div>
        </Show>

        <Show when={props.linkResult === 'linked'}>
          <p class="notice inbox-note" role="status">
            Gmail connected.
          </p>
        </Show>
        <Show when={props.linkResult === 'failed'}>
          <p class="error inbox-note" role="alert">
            Gmail wasn't connected. Allow read access to your mail on Google's screen and try again.
          </p>
        </Show>
        <For each={problems()}>{(p) => <p class="error inbox-note" role="alert">{p}</p>}</For>
        <Show when={error()}>
          <p class="error inbox-note" role="alert">{error()}</p>
        </Show>

        <Show when={!accounts.error && !messages.error} fallback={<p class="error inbox-empty">Could not load your mail.</p>}>
          <Show
            when={refreshing() || (!accounts.loading && !messages.loading)}
            fallback={<p class="muted inbox-empty">Loading…</p>}
          >
            <Show
              when={openId()}
              fallback={
                <Show
                  when={visible().length}
                  fallback={
                    <p class="muted inbox-empty">
                      {!accounts()?.length
                        ? 'No accounts connected. Connect a Gmail account to import its mail.'
                        : selectedAccount()?.message_count
                          ? `Nothing in ${folderName()}.`
                          : 'No messages yet.'}
                    </p>
                  }
                >
                  <ul class="message-list">
                    <For each={visible()}>
                      {(m) => (
                        <li>
                          <button
                            class="message-row"
                            classList={{ unread: m.labels.includes('UNREAD') }}
                            onClick={() => setOpenId(m.id)}
                          >
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
                              <For each={m.labels.filter((l) => l !== folder() && userLabel(l))}>
                                {(l) => (
                                  <span
                                    class="m-label"
                                    style={{ 'border-color': userLabel(l)?.color ?? 'var(--border)' }}
                                  >
                                    {userLabel(l)?.name}
                                  </span>
                                )}
                              </For>
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

  // Signed in on /auth/signin or /auth/register: those pages don't apply, go
  // home. Signed out on /settings: sign in first.
  createEffect(() => {
    if (me() && (view() === 'signin' || view() === 'register')) navigate('home', true)
    if (!me.loading && !me.error && me() === null && view() === 'settings') navigate('signin', true)
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
              {/* Just the name; the email only for an account without one. */}
              <strong>{[user().first_name, user().last_name].filter(Boolean).join(' ') || user().email}</strong>
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
                  <SignIn failed={loginFailed} onRegister={() => navigate('register')} />
                </Match>
                <Match when={view() === 'register'}>
                  <Register onCancel={() => navigate('signin')} />
                </Match>
                <Match when={view() === 'home'}>
                  <Welcome />
                </Match>
              </Switch>
            }
          >
            <Show
              when={view() === 'settings' && me()}
              fallback={
                <Mail
                  onSignedOut={() => mutate(null)}
                  linkResult={linkResult}
                  primaryEmail={me()?.email ?? ''}
                  settingsLink={linkTo('settings')}
                />
              }
            >
              {(user) => (
                <Settings
                  me={user()}
                  onUpdated={mutate}
                  onSignedOut={() => mutate(null)}
                  onSignOut={signOut}
                  backLink={linkTo('home')}
                />
              )}
            </Show>
          </Show>
        </Show>
      </Show>
      </main>
    </>
  )
}

export default App
