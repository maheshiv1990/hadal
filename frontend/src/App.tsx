import { createEffect, createResource, createSignal, For, Show } from 'solid-js'
import {
  api,
  LOGIN_PATH,
  MAX_PASSWORD_LENGTH,
  MIN_PASSWORD_LENGTH,
  UnauthorizedError,
  type Me,
} from './api'

type AuthView = 'signin' | 'register'

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
      <p>Sign in to see your notes.</p>
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

function Notes(props: { onSignedOut: () => void }) {
  const [notes, { refetch }] = createResource(api.listNotes)
  const [title, setTitle] = createSignal('')
  const [body, setBody] = createSignal('')
  const [error, setError] = createSignal<string | null>(null)
  const [saving, setSaving] = createSignal(false)

  // Any 401 means the session ended (expired, or logged out elsewhere).
  const handle = (err: unknown) => {
    if (err instanceof UnauthorizedError) props.onSignedOut()
    else setError((err as Error).message)
  }

  const submit = async (e: SubmitEvent) => {
    e.preventDefault()
    setError(null)
    setSaving(true)
    try {
      await api.createNote(title(), body())
      setTitle('')
      setBody('')
      await refetch()
    } catch (err) {
      handle(err)
    } finally {
      setSaving(false)
    }
  }

  const remove = async (id: string) => {
    setError(null)
    try {
      await api.deleteNote(id)
      await refetch()
    } catch (err) {
      handle(err)
    }
  }

  createEffect(() => {
    if (notes.error instanceof UnauthorizedError) props.onSignedOut()
  })

  return (
    <>
      <form onSubmit={submit}>
        <input
          placeholder="Title"
          value={title()}
          onInput={(e) => setTitle(e.currentTarget.value)}
          maxLength={200}
          required
        />
        <textarea
          placeholder="Write something…"
          value={body()}
          onInput={(e) => setBody(e.currentTarget.value)}
          maxLength={10000}
          rows={4}
        />
        <button type="submit" disabled={saving()}>
          {saving() ? 'Saving…' : 'Add note'}
        </button>
      </form>

      <Show when={error()}>
        <p class="error" role="alert">{error()}</p>
      </Show>

      <Show when={!notes.error} fallback={<p class="error">Could not load notes: {notes.error?.message}</p>}>
        <Show when={!notes.loading} fallback={<p class="muted">Loading…</p>}>
          <Show when={notes()?.length} fallback={<p class="muted">No notes yet.</p>}>
            <ul class="notes">
              <For each={notes()}>
                {(note) => (
                  <li>
                    <div>
                      <strong>{note.title}</strong>
                      <Show when={note.body}>
                        <p>{note.body}</p>
                      </Show>
                      <time class="muted">{new Date(note.created_at).toLocaleString()}</time>
                    </div>
                    <button class="secondary" onClick={() => remove(note.id)} aria-label={`Delete ${note.title}`}>
                      Delete
                    </button>
                  </li>
                )}
              </For>
            </ul>
          </Show>
        </Show>
      </Show>
    </>
  )
}

function App() {
  const [me, { mutate }] = createResource<Me | null>(api.me)
  const [view, setView] = createSignal<AuthView>('signin')
  const loginFailed = new URLSearchParams(window.location.search).get('login') === 'failed'
  if (loginFailed) {
    // Drop the flag so a reload doesn't show the error again.
    window.history.replaceState(null, '', window.location.pathname)
  }

  const signOut = async () => {
    try {
      await api.logout()
    } finally {
      mutate(null)
      setView('signin')
    }
  }

  return (
    <main>
      <header class="bar">
        <h1>Hadal</h1>
        <Show when={me()}>
          {(user) => (
            <div class="user">
              <span class="muted">{user().email}</span>
              <button class="secondary" onClick={signOut}>
                Sign out
              </button>
            </div>
          )}
        </Show>
      </header>

      <Show when={!me.error} fallback={<p class="error">Could not reach the server.</p>}>
        <Show when={!me.loading} fallback={<p class="muted">Loading…</p>}>
          <Show
            when={me()}
            fallback={
              <Show
                when={view() === 'register'}
                fallback={
                  <SignIn failed={loginFailed} onSignedIn={mutate} onRegister={() => setView('register')} />
                }
              >
                <Register onSignedIn={mutate} onCancel={() => setView('signin')} />
              </Show>
            }
          >
            <Notes onSignedOut={() => mutate(null)} />
          </Show>
        </Show>
      </Show>
    </main>
  )
}

export default App
