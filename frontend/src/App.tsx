import { createResource, createSignal, For, Show } from 'solid-js'
import { api } from './api'

function App() {
  const [notes, { refetch }] = createResource(api.listNotes)
  const [title, setTitle] = createSignal('')
  const [body, setBody] = createSignal('')
  const [error, setError] = createSignal<string | null>(null)
  const [saving, setSaving] = createSignal(false)

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
      setError((err as Error).message)
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
      setError((err as Error).message)
    }
  }

  return (
    <main>
      <h1>Hadal</h1>

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
    </main>
  )
}

export default App
