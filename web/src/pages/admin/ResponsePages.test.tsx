import { fireEvent, screen, waitForElementToBeRemoved, within } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import type { AdminUserView, AnomalyView, Inbox, ResponseJobView } from '../../api/types'
import { renderWithAuth } from '../../test/renderWithAuth'
import { AnomalyDetailPage } from './AnomalyDetailPage'
import { JobsPage } from './JobsPage'
import { NotificationsPage } from './NotificationsPage'
import { UsersPage } from './UsersPage'
import { Route, Routes } from 'react-router'

const job: ResponseJobView = {
  id: 'j1',
  anomalyId: 'a1',
  userId: 'u2',
  action: 'revoke_and_lock',
  status: 'dead',
  attempts: 5,
  lastError: 'TimeoutException: redis',
  createdAt: '2026-10-24T08:00:00Z',
  nextAttemptAt: '2026-10-24T08:01:00Z',
  revokedAt: '2026-10-24T08:00:01Z',
  notifiedAt: null,
  finishedAt: '2026-10-24T08:05:00Z',
}

describe('NotificationsPage', () => {
  it('shows grouped entries and marks them read', async () => {
    let inbox: Inbox = {
      unread: 1,
      items: [{ id: 'n1', title: 'Tor exit node: Ben', anomalyId: 'a1', lastAnomalyId: 'a3', subjectUserId: 'u2', count: 3, createdAt: '', updatedAt: '2026-10-24T08:00:00Z', readAt: null }],
    }
    const call = renderWithAuth(<NotificationsPage />, (path) => {
      if (path === '/api/admin/notifications/n1/read') {
        inbox = { unread: 0, items: inbox.items.map((i) => ({ ...i, readAt: '2026-10-24T09:00:00Z' })) }
        return undefined
      }
      return inbox
    })

    expect(await screen.findByRole('link', { name: 'Tor exit node: Ben' })).toHaveAttribute('href', '/admin/anomalies/a3')
    expect(screen.getByText('×3')).toBeInTheDocument()

    const button = screen.getByRole('button', { name: 'Mark as read' })
    fireEvent.click(button)

    await waitForElementToBeRemoved(button)
    expect(screen.getByText('×3')).toBeInTheDocument()
    expect(call).toHaveBeenCalledWith('/api/admin/notifications/n1/read', { method: 'POST' })
  })
})

describe('JobsPage', () => {
  it('offers Retry on dead jobs', async () => {
    const call = renderWithAuth(<JobsPage />, (path) => (path.endsWith('/retry') ? undefined : [job]))

    fireEvent.click(await screen.findByRole('button', { name: 'Retry' }))

    expect(await screen.findByRole('status')).toHaveTextContent('Job queued again.')
    expect(call).toHaveBeenCalledWith('/api/admin/response-jobs/j1/retry', { method: 'POST' })
    expect(screen.getByText('TimeoutException: redis')).toBeInTheDocument()
  })
})

describe('UsersPage', () => {
  it('shows locked users with an Unlock button', async () => {
    let locked = true
    const users = (): AdminUserView[] => [
      {
        id: 'u2',
        email: 'ben@acme.test',
        displayName: 'Ben',
        roles: ['member'],
        createdAt: '',
        securityLockedAt: locked ? '2026-10-24T08:00:00Z' : null,
        securityLockedReason: locked ? 'tor' : null,
      },
    ]
    renderWithAuth(<UsersPage />, (path) => {
      if (path === '/api/admin/users/u2/unlock') {
        locked = false
        return undefined
      }
      return users()
    })

    const row = (await screen.findByText('Ben')).closest('tr')!
    expect(within(row).getByText('Locked (tor)')).toBeInTheDocument()

    fireEvent.click(within(row).getByRole('button', { name: 'Unlock' }))

    expect(await screen.findByRole('status')).toHaveTextContent('Unlocked Ben')
    expect(await within(row).findByText('Active')).toBeInTheDocument()
  })
})

describe('AnomalyDetailPage', () => {
  it('shows the response timeline', async () => {
    const anomaly: AnomalyView = {
      id: 'a1',
      detector: 'tor',
      severity: 'critical',
      userId: 'u2',
      userName: 'Ben',
      sessionId: null,
      detectedAt: '2026-10-24T08:00:00Z',
      eventCount: 1,
      eventIds: ['e1'],
      evidence: {},
      decision: 'responded',
      decisionReason: 'mode_respond',
      policyVersion: 2,
      response: job,
      revokedSessions: 2,
    }
    renderWithAuth(
      <Routes>
        <Route path="/admin/anomalies/:id" element={<AnomalyDetailPage />} />
      </Routes>,
      () => anomaly,
      { route: '/admin/anomalies/a1' },
    )

    expect(await screen.findByText(/2 session\(s\) revoked and account locked/)).toBeInTheDocument()
    expect(screen.getByText(/dead after 5 attempt/)).toBeInTheDocument()
  })
})
