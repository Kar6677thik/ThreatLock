import { render } from '@testing-library/react'
import type { ReactNode } from 'react'
import { MemoryRouter } from 'react-router'
import { vi } from 'vitest'
import type { UserView } from '../api/types'
import { AuthContext, type AuthValue, type CallOptions } from '../auth/useAuth'

export const owner: UserView = {
  id: 'u-owner',
  email: 'asha@acme.test',
  displayName: 'Asha',
  orgId: 'o1',
  orgName: 'Acme',
  orgSlug: 'acme',
  roles: ['member', 'owner'],
}

export type FakeApi = (path: string, options?: CallOptions) => unknown

/**
 * Renders a page with a fake signed-in session. `api` answers each call by path (and options);
 * the returned `call` mock records what the page sent, so tests can assert on request bodies.
 */
export function renderWithAuth(ui: ReactNode, api: FakeApi, { user = owner, route = '/' } = {}) {
  const call = vi.fn(async (path: string, options?: CallOptions) => {
    const result = api(path, options)
    if (result instanceof Error) throw result
    return result
  })
  const value: AuthValue = {
    status: 'signed-in',
    session: { token: 't', expiresAt: '2030-01-01T00:00:00Z', user },
    signedOutReason: null,
    login: vi.fn(),
    register: vi.fn(),
    logout: vi.fn(),
    call: call as AuthValue['call'],
    callRaw: vi.fn(),
  }
  render(
    <MemoryRouter initialEntries={[route]}>
      <AuthContext.Provider value={value}>{ui}</AuthContext.Provider>
    </MemoryRouter>,
  )
  return call
}
