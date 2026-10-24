import { fireEvent, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from './App'

const user = { id: 'u1', email: 'asha@acme.test', displayName: 'Asha', orgId: 'o1', orgName: 'Acme', orgSlug: 'acme', roles: ['member', 'owner'] }
const notes = [{ id: 'n1', title: 'Team plan', shared: true, isOwner: true, ownerName: 'Asha', updatedAt: '' }]

function json(body: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }))
}

const loginOk = () => json({ accessToken: 'fresh', expiresAt: '2030-01-01T00:00:00Z', user })
const unauthorized = (detail = 'Not signed in.') => json({ status: 401, detail }, 401)

type Handler = (url: string, init?: RequestInit) => Promise<Response>

// A tiny fake API: each URL gets a handler, so the whole app runs without a server.
function stubApi(handlers: Record<string, Handler>) {
  const fetchMock = vi.fn((url: string, init?: RequestInit) =>
    (handlers[url] ?? (() => json({ status: 'Healthy', checks: {} })))(url, init),
  )
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

async function signIn() {
  fireEvent.change(await screen.findByLabelText('Email'), { target: { value: 'asha@acme.test' } })
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'correct horse battery' } })
  fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))
}

describe('App', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('shows the API error when sign-in fails', async () => {
    stubApi({
      '/api/auth/refresh': () => unauthorized(),
      '/api/auth/login': () => unauthorized('Invalid email or password.'),
    })
    render(<App />)

    await signIn()

    expect(await screen.findByRole('alert')).toHaveTextContent('Invalid email or password.')
  })

  it('explains a security lock instead of "wrong password"', async () => {
    const detail = 'Your account was locked after suspicious activity. Ask an administrator to unlock it.'
    stubApi({
      '/api/auth/refresh': () => unauthorized(),
      '/api/auth/login': () => json({ status: 403, detail, code: 'account_locked' }, 403),
    })
    render(<App />)

    await signIn()

    expect(await screen.findByRole('alert')).toHaveTextContent('locked after suspicious activity')
  })

  it('restores the session from the refresh cookie on page load', async () => {
    const fetchMock = stubApi({
      '/api/auth/refresh': loginOk,
      '/api/notes': () => json(notes),
    })

    render(<App />)

    expect(await screen.findByText('Team plan')).toBeInTheDocument()
    const refreshCall = fetchMock.mock.calls.find(([url]) => url === '/api/auth/refresh')
    const headers = (refreshCall?.[1]?.headers ?? {}) as Record<string, string>
    expect(headers['X-Requested-With']).toBe('threatlock')
  })

  it('refreshes once and retries when the access token has expired', async () => {
    let notesCalls = 0
    stubApi({
      '/api/auth/refresh': (() => {
        let calls = 0
        // First call (page load): no session yet. Later: the cookie is valid.
        return () => (calls++ === 0 ? unauthorized() : loginOk())
      })(),
      '/api/auth/login': () => json({ accessToken: 'stale', expiresAt: '2030-01-01T00:00:00Z', user }),
      '/api/notes': (_url, init) => {
        notesCalls++
        const auth = ((init?.headers ?? {}) as Record<string, string>).Authorization
        return auth === 'Bearer fresh' ? json(notes) : unauthorized()
      },
    })
    render(<App />)

    await signIn()

    expect(await screen.findByText('Team plan')).toBeInTheDocument()
    expect(notesCalls).toBe(2)   // once with the stale token, once after refreshing
  })

  it('returns to sign-in with a message when the session was revoked', async () => {
    stubApi({
      '/api/auth/refresh': (() => {
        let calls = 0
        return () => (calls++ === 0 ? loginOk() : unauthorized('Your session has ended.'))
      })(),
      '/api/notes': () => unauthorized(),
    })

    render(<App />)

    expect(await screen.findByRole('status')).toHaveTextContent('You were signed out')
    expect(screen.getByRole('button', { name: 'Sign in' })).toBeInTheDocument()
  })

  it('shows admin screens only to admins', async () => {
    stubApi({ '/api/auth/refresh': () => json({ accessToken: 't', expiresAt: '2030-01-01T00:00:00Z', user: { ...user, roles: ['member'] } }), '/api/notes': () => json([]) })

    render(<App />)

    expect(await screen.findByRole('link', { name: 'Notes' })).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Anomalies' })).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Policy' })).not.toBeInTheDocument()
  })

  it('shows owners the anomalies, users and policy screens', async () => {
    stubApi({ '/api/auth/refresh': loginOk, '/api/notes': () => json([]) })

    render(<App />)

    for (const name of ['Anomalies', 'Users', 'Policy', 'Jobs']) {
      expect(await screen.findByRole('link', { name })).toBeInTheDocument()
    }
  })

  it('shows admins how many notifications are unread', async () => {
    stubApi({
      '/api/auth/refresh': loginOk,
      '/api/notes': () => json([]),
      '/api/admin/notifications?unreadOnly=true': () => json({ unread: 3, items: [] }),
    })

    render(<App />)

    expect(await screen.findByLabelText('3 unread')).toHaveTextContent('3')
  })
})
