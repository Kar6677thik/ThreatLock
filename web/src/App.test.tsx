import { fireEvent, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from './App'

const user = { id: 'u1', email: 'asha@acme.test', displayName: 'Asha', orgId: 'o1', orgName: 'Acme', orgSlug: 'acme', roles: ['member', 'owner'] }

function json(body: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }))
}

// A tiny fake API: answers by URL, so the whole app can run without a server.
function stubApi(loginStatus: number) {
  vi.stubGlobal(
    'fetch',
    vi.fn((url: string) => {
      if (url === '/api/auth/login')
        return loginStatus === 200
          ? json({ accessToken: 't', expiresAt: '2030-01-01T00:00:00Z', user })
          : json({ status: 401, detail: 'Invalid email or password.' }, 401)
      if (url === '/api/notes') return json([{ id: 'n1', title: 'Team plan', shared: true, isOwner: true, ownerName: 'Asha', updatedAt: '' }])
      if (url === '/api/info') return json({ name: 'ThreatLock', version: '1', environment: 'Test' })
      return json({ status: 'Healthy', checks: {} })
    }),
  )
}

async function signIn() {
  render(<App />)
  fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'asha@acme.test' } })
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'correct horse battery' } })
  fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))
}

describe('App', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('shows the API error when sign-in fails', async () => {
    stubApi(401)

    await signIn()

    expect(await screen.findByRole('alert')).toHaveTextContent('Invalid email or password.')
  })

  it('shows the user and their notes after signing in', async () => {
    stubApi(200)

    await signIn()

    expect(await screen.findByText('Team plan')).toBeInTheDocument()
    expect(screen.getByText(/Asha · Acme/)).toBeInTheDocument()
  })
})
