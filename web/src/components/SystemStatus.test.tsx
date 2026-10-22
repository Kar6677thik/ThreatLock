import { render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { SystemStatus } from './SystemStatus'

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

// Replace the browser's fetch with a fake that answers by URL, so the test needs no server.
function stubApi(readiness: { status: string; checks: Record<string, string> }, readyStatus: number) {
  vi.stubGlobal(
    'fetch',
    vi.fn((url: string) =>
      Promise.resolve(
        url === '/api/info'
          ? jsonResponse({ name: 'ThreatLock', version: '1.0.0+abc', environment: 'Development' })
          : jsonResponse(readiness, readyStatus),
      ),
    ),
  )
}

describe('SystemStatus', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('shows version and healthy dependencies', async () => {
    stubApi({ status: 'Healthy', checks: { postgres: 'Healthy', redis: 'Healthy' } }, 200)

    render(<SystemStatus />)

    expect(await screen.findByText('1.0.0+abc')).toBeInTheDocument()
    expect(screen.getByText('postgres: Healthy')).toBeInTheDocument()
  })

  it('treats a 503 from /readyz as an answer and names the failing dependency', async () => {
    stubApi({ status: 'Unhealthy', checks: { postgres: 'Healthy', redis: 'Unhealthy' } }, 503)

    render(<SystemStatus />)

    expect(await screen.findByText('Unhealthy')).toBeInTheDocument()
    expect(screen.getByText('redis: Unhealthy')).toBeInTheDocument()
  })

  it('shows an alert when the API cannot be reached', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new TypeError('Failed to fetch'))))

    render(<SystemStatus />)

    expect(await screen.findByRole('alert')).toHaveTextContent('Failed to fetch')
  })
})
