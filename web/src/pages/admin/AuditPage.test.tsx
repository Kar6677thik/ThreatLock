import { fireEvent, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import type { AuditEntryView, VerifyResult } from '../../api/types'
import type { CallOptions } from '../../auth/useAuth'
import { renderWithAuth } from '../../test/renderWithAuth'
import { AuditPage } from './AuditPage'

const entry = (seq: number, action: string): AuditEntryView => ({
  seq,
  occurredAt: '2026-10-24T08:00:00Z',
  actorType: 'admin',
  actorId: 'u1',
  actorName: 'Asha',
  action,
  targetType: 'user',
  targetId: 'u2u2u2u2-0000',
  anomalyId: null,
  details: { email: 'ben@acme.test' },
  prevHash: '0'.repeat(64),
  entryHash: 'ab'.repeat(32),
})

function api(verify: (body: unknown) => VerifyResult) {
  return (path: string, options?: CallOptions) =>
    path === '/api/admin/audit/verify' ? verify(options?.body) : [entry(1, 'org.created'), entry(2, 'user.created')]
}

describe('AuditPage', () => {
  it('lists entries with their hashes', async () => {
    renderWithAuth(<AuditPage />, api(() => ({ ok: true, entries: 2, head: 'ab'.repeat(32) })))

    expect(await screen.findByText('user.created')).toBeInTheDocument()
    expect(screen.getAllByText('abababababab…')).toHaveLength(2)
  })

  it('reports an intact chain and offers its head as an anchor', async () => {
    renderWithAuth(<AuditPage />, api(() => ({ ok: true, entries: 2, head: 'cd'.repeat(32) })))

    fireEvent.click(await screen.findByRole('button', { name: 'Verify chain' }))

    const status = await screen.findByRole('status')
    expect(status).toHaveTextContent('Intact. 2 entries')
    expect(status).toHaveTextContent('cd'.repeat(32))
  })

  it('names the first broken entry and sends an anchor when given one', async () => {
    let sent: unknown
    renderWithAuth(<AuditPage />, api((body) => {
      sent = body
      return { ok: false, entries: 1, head: null, firstBrokenSeq: 2, reason: 'hash_mismatch' }
    }))

    fireEvent.change(await screen.findByLabelText('Anchor seq'), { target: { value: '2' } })
    fireEvent.change(screen.getByLabelText('Anchor hash'), { target: { value: 'ab'.repeat(32) } })
    fireEvent.click(screen.getByRole('button', { name: 'Verify chain' }))

    expect(await screen.findByRole('status')).toHaveTextContent('Tampered. Entry 2 fails: its contents no longer match its hash')
    expect(sent).toEqual({ anchor: { seq: 2, hash: 'ab'.repeat(32) } })
  })
})
