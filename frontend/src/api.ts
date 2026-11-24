export interface Note {
  id: string
  title: string
  body: string
  created_at: string
}

export interface Me {
  email: string
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

/** Starts Google sign-in. A plain link: the server redirects to Google. */
export const LOGIN_PATH = '/api/auth/login'

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
  // JSON body so a cross-site form can't log the user out (CASA 3.1.5).
  logout: () => request<void>('/auth/logout', { method: 'POST', body: '{}' }),
  listNotes: () => request<Note[]>('/notes'),
  createNote: (title: string, body: string) =>
    request<Note>('/notes', { method: 'POST', body: JSON.stringify({ title, body }) }),
  deleteNote: (id: string) => request<void>(`/notes/${id}`, { method: 'DELETE' }),
}
