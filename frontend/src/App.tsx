import { createEffect, createResource, createSignal, For, Match, onCleanup, Show, Switch } from 'solid-js'
import {
  api,
  GMAIL_CONNECT_PATH,
  LOGIN_PATH,
  MAX_PASSWORD_LENGTH,
  MIN_PASSWORD_LENGTH,
  UnauthorizedError,
  type MailAccount,
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

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`

/**
 * Linked Gmail mailboxes and their imported mail. Bodies are plain text from
 * the server and are only ever shown as text (CASA 5.1.7).
 */
function Mail(props: { onSignedOut: () => void; linkResult: LinkResult }) {
  const [accounts, { refetch: refetchAccounts }] = createResource(api.listMailAccounts)
  const [messages, { refetch: refetchMessages }] = createResource(api.listMessages)
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

  const disconnect = async (account: MailAccount) => {
    if (!window.confirm(`Disconnect ${account.email}? Its imported mail will be deleted from Hadal.`)) {
      return
    }
    setError(null)
    try {
      await api.disconnectMailAccount(account.id)
      setOpenId(null)
      await Promise.all([refetchAccounts(), refetchMessages()])
    } catch (err) {
      handle(err)
    }
  }

  const toggle = (id: string) => setOpenId(openId() === id ? null : id)

  return (
    <section class="panel mail">
      <div class="mail-head">
        <h2>Email</h2>
        <div class="mail-actions">
          <a class="button outline" href={GMAIL_CONNECT_PATH}>
            Connect Gmail
          </a>
          <button onClick={importAll} disabled={importing() || !accounts()?.length}>
            {importing() ? 'Importing…' : 'Import all'}
          </button>
        </div>
      </div>

      <Show when={props.linkResult === 'linked'}>
        <p class="notice" role="status">Gmail connected. Use “Import all” to fetch its mail.</p>
      </Show>
      <Show when={props.linkResult === 'failed'}>
        <p class="error" role="alert">
          Gmail wasn't connected. Allow read access to your mail on Google's screen and try again.
        </p>
      </Show>

      <Show when={!accounts.error} fallback={<p class="error">Could not load mailboxes.</p>}>
        <Show
          when={accounts()?.length}
          fallback={
            <Show when={!accounts.loading}>
              <p class="muted">No mailboxes connected. Connect a Gmail account to import its newest 100 messages.</p>
            </Show>
          }
        >
          <ul class="mail-accounts">
            <For each={accounts()}>
              {(account) => (
                <li>
                  <div>
                    <strong>{account.email}</strong>
                    <span class="muted">
                      {' · '}
                      {plural(account.message_count, 'message', 'messages')}
                      {account.last_import_at ? ` · imported ${formatDate(account.last_import_at)}` : ' · not imported yet'}
                    </span>
                  </div>
                  <button class="secondary" onClick={() => disconnect(account)} aria-label={`Disconnect ${account.email}`}>
                    Disconnect
                  </button>
                </li>
              )}
            </For>
          </ul>
        </Show>
      </Show>

      <Show when={status()}>
        <p class="notice" role="status">{status()}</p>
      </Show>
      <For each={problems()}>{(p) => <p class="error" role="alert">{p}</p>}</For>
      <Show when={error()}>
        <p class="error" role="alert">{error()}</p>
      </Show>

      <Show when={!messages.error} fallback={<p class="error">Could not load messages.</p>}>
        <Show when={messages()?.length}>
          <ul class="messages">
            <For each={messages()}>
              {(m) => (
                <li classList={{ open: openId() === m.id }}>
                  <button class="message-row" onClick={() => toggle(m.id)} aria-expanded={openId() === m.id}>
                    <span class="message-top">
                      <strong>{m.subject || '(no subject)'}</strong>
                      <time class="muted">{formatDate(m.received_at)}</time>
                    </span>
                    <span class="muted">
                      {m.from}
                      <Show when={(accounts()?.length ?? 0) > 1}> → {m.account_email}</Show>
                    </span>
                    <span class="snippet">{m.snippet}</span>
                  </button>
                  <Show when={openId() === m.id}>
                    <Show
                      when={!detail.error}
                      fallback={<p class="error">Could not open this message.</p>}
                    >
                      <Show
                        when={!detail.loading && detail()?.id === m.id ? detail() : undefined}
                        fallback={<p class="muted">Loading…</p>}
                      >
                        {(d) => (
                          <div class="message-body">
                            <p class="muted">To: {d().to || '(none)'}</p>
                            <pre>{d().body || '(This message has no text.)'}</pre>
                          </div>
                        )}
                      </Show>
                    </Show>
                  </Show>
                </li>
              )}
            </For>
          </ul>
        </Show>
      </Show>
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
        <div class="site-header-inner">
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

      <main>
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
            <Mail onSignedOut={() => mutate(null)} linkResult={linkResult} />
          </Show>
        </Show>
      </Show>
      </main>
    </>
  )
}

export default App
