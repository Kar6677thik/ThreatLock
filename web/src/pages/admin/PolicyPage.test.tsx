import { fireEvent, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { ApiError } from '../../api/client'
import type { PolicyView, SecurityPolicy } from '../../api/types'
import { renderWithAuth } from '../../test/renderWithAuth'
import { PolicyPage } from './PolicyPage'

const policy: SecurityPolicy = {
  trustedNetworks: [],
  excludedUserIds: [],
  excludedRoles: [],
  notifyRoles: ['owner', 'admin', 'security_admin'],
  detectors: {
    tor: { mode: 'respond', minSeverity: 'high' },
    impossible_travel: { mode: 'notify', minSeverity: 'low', thresholds: { maxSpeedKmh: 900, minDistanceKm: 500 } },
  },
  response: { action: 'revoke_sessions', lockOnSeverity: 'critical' },
}
const view: PolicyView = { version: 3, updatedAt: '2026-10-24T08:00:00Z', updatedBy: 'Asha', policy }

function api(onPut: (body: unknown) => unknown) {
  return (path: string, options?: { method?: string; body?: unknown }) => {
    if (path === '/api/admin/policy' && options?.method === 'PUT') return onPut(options.body)
    if (path === '/api/admin/policy') return view
    if (path === '/api/admin/users') return [{ id: 'u2', email: 'ben@acme.test', displayName: 'Ben', roles: ['member'], createdAt: '' }]
    if (path === '/api/admin/policy/versions') return [{ version: 3, updatedAt: '2026-10-24T08:00:00Z', updatedBy: 'Asha' }]
    throw new Error(`unexpected ${path}`)
  }
}

describe('PolicyPage', () => {
  it('saves the edited policy with the version it was loaded from', async () => {
    let sent: { expectedVersion: number; policy: SecurityPolicy } | undefined
    renderWithAuth(<PolicyPage />, api((body) => {
      sent = body as typeof sent
      return { ...view, version: 4 }
    }))

    fireEvent.change(await screen.findByLabelText('Tor exit node (D1) mode'), { target: { value: 'observe' } })
    fireEvent.change(screen.getByLabelText(/Trusted networks/), { target: { value: '203.0.113.0/24\n\n 198.51.100.7 ' } })
    fireEvent.click(screen.getByLabelText(/Ben/))
    fireEvent.click(screen.getByRole('button', { name: 'Save policy' }))

    expect(await screen.findByRole('status')).toHaveTextContent('Saved as version 4')
    expect(sent?.expectedVersion).toBe(3)
    expect(sent?.policy.detectors.tor.mode).toBe('observe')
    expect(sent?.policy.trustedNetworks).toEqual(['203.0.113.0/24', '198.51.100.7'])
    expect(sent?.policy.excludedUserIds).toEqual(['u2'])
  })

  it('explains a conflict instead of overwriting someone else’s change', async () => {
    renderWithAuth(<PolicyPage />, api(() => new ApiError(409, { status: 409, detail: 'Someone else changed the policy since you loaded it.' })))

    fireEvent.click(await screen.findByRole('button', { name: 'Save policy' }))

    expect(await screen.findByRole('alert')).toHaveTextContent('Someone else changed the policy')
    expect(screen.getByRole('button', { name: 'Reload the latest version' })).toBeInTheDocument()
  })

  it('shows field errors from validation', async () => {
    renderWithAuth(<PolicyPage />, api(() => new ApiError(400, { status: 400, errors: { trustedNetworks: ["'office' is not a CIDR network such as 203.0.113.0/24."] } })))

    fireEvent.click(await screen.findByRole('button', { name: 'Save policy' }))

    expect(await screen.findByRole('alert')).toHaveTextContent("'office' is not a CIDR network")
  })
})
