import { fireEvent, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import type { AnomalyView } from '../../api/types'
import { renderWithAuth } from '../../test/renderWithAuth'
import { AnomaliesPage } from './AnomaliesPage'

const anomaly: AnomalyView = {
  id: 'a1',
  detector: 'tor',
  severity: 'high',
  userId: 'u2',
  userName: 'Ben',
  sessionId: 's1',
  detectedAt: '2026-10-24T08:00:00Z',
  eventCount: 2,
  eventIds: ['e1', 'e2'],
  evidence: { ip: '198.51.100.77' },
  decision: 'responded',
  decisionReason: 'mode_respond',
  policyVersion: 0,
}

describe('AnomaliesPage', () => {
  it('lists anomalies with their decision', async () => {
    renderWithAuth(<AnomaliesPage />, () => [anomaly])

    expect(await screen.findByText('Ben')).toBeInTheDocument()
    expect(screen.getByRole('cell', { name: 'Tor exit node (D1)' })).toBeInTheDocument()
    expect(screen.getByRole('cell', { name: 'responded' })).toHaveAttribute('title', 'mode_respond')
  })

  it('sends filters to the API and keeps them in the URL', async () => {
    const call = renderWithAuth(<AnomaliesPage />, () => [anomaly], { route: '/admin/anomalies?detector=tor' })
    await screen.findByText('Ben')

    fireEvent.change(screen.getByLabelText('Decision'), { target: { value: 'notified' } })

    await screen.findByText('Ben')
    const paths = call.mock.calls.map(([path]) => path)
    expect(paths[0]).toBe('/api/admin/anomalies?detector=tor')
    expect(paths.at(-1)).toBe('/api/admin/anomalies?detector=tor&decision=notified')
  })
})
