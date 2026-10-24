import { useEffect, useState, type FormEvent } from 'react'
import { Link } from 'react-router'
import { ApiError } from '../../api/client'
import type { AuditEntryView, VerifyResult } from '../../api/types'
import { useAuth } from '../../auth/useAuth'

const PAGE = 100

const REASONS: Record<string, string> = {
  hash_mismatch: 'its contents no longer match its hash: the entry was edited',
  chain_break: "it no longer points at the previous entry's hash: something before it was changed or removed",
  seq_gap: 'this sequence number is missing: an entry was deleted',
  anchor_mismatch: 'it does not match the saved anchor: the chain was rewritten or cut short since then',
}

function short(hash: string) {
  return `${hash.slice(0, 12)}…`
}

/**
 * The org's tamper-evident audit log (SPEC §11). Each entry's hash covers the previous entry's
 * hash, so "Verify" can say exactly where the history was changed. An *anchor* (a seq and hash
 * saved outside ThreatLock) also catches a rewrite of everything after some point.
 */
export function AuditPage() {
  const { call } = useAuth()
  const [entries, setEntries] = useState<AuditEntryView[]>([])
  const [more, setMore] = useState(false)
  const [result, setResult] = useState<VerifyResult | null>(null)
  const [anchor, setAnchor] = useState({ seq: '', hash: '' })
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    call<AuditEntryView[]>(`/api/admin/audit?limit=${PAGE}`).then((page) => {
      setEntries(page)
      setMore(page.length === PAGE)
    })
  }, [call])

  async function loadMore() {
    const page = await call<AuditEntryView[]>(`/api/admin/audit?afterSeq=${entries.at(-1)?.seq ?? 0}&limit=${PAGE}`)
    setEntries([...entries, ...page])
    setMore(page.length === PAGE)
  }

  async function verify(event?: FormEvent) {
    event?.preventDefault()
    setError(null)
    const body = anchor.seq && anchor.hash ? { anchor: { seq: Number(anchor.seq), hash: anchor.hash.trim() } } : {}
    try {
      setResult(await call<VerifyResult>('/api/admin/audit/verify', { method: 'POST', body }))
    } catch (e) {
      setError(e instanceof ApiError ? e.messages.join(' ') : String(e))
    }
  }

  return (
    <section>
      <h2>Audit log</h2>
      <form onSubmit={(e) => void verify(e)} className="row">
        <button type="submit">Verify chain</button>
        <label>
          Anchor seq <input value={anchor.seq} onChange={(e) => setAnchor({ ...anchor, seq: e.target.value })} inputMode="numeric" size={6} />
        </label>
        <label>
          Anchor hash <input value={anchor.hash} onChange={(e) => setAnchor({ ...anchor, hash: e.target.value })} size={40} />
        </label>
      </form>
      {error && <p role="alert">{error}</p>}
      {result && (
        <div role="status" className={result.ok ? 'verified' : 'tampered'}>
          {result.ok ? (
            <>
              <p>
                <strong>Intact.</strong> {result.entries} entries, every hash checks out.
              </p>
              {result.head && (
                <p>
                  To detect a future rewrite, save this anchor somewhere outside ThreatLock: seq <code>{result.entries}</code>, hash{' '}
                  <code>{result.head}</code>
                </p>
              )}
            </>
          ) : (
            <p>
              <strong>Tampered.</strong> Entry {result.firstBrokenSeq} fails: {REASONS[result.reason ?? ''] ?? result.reason}. The{' '}
              {result.entries} entries before it check out.
            </p>
          )}
        </div>
      )}
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>When</th>
            <th>Actor</th>
            <th>Action</th>
            <th>Target</th>
            <th>Details</th>
            <th>Hash</th>
          </tr>
        </thead>
        <tbody>
          {entries.map((e) => (
            <tr key={e.seq} className={result && !result.ok && e.seq === result.firstBrokenSeq ? 'tampered' : undefined}>
              <td>{e.seq}</td>
              <td>{new Date(e.occurredAt).toLocaleString()}</td>
              <td>{e.actorName ?? e.actorType}</td>
              <td>
                {e.anomalyId ? <Link to={`/admin/anomalies/${e.anomalyId}`}>{e.action}</Link> : e.action}
              </td>
              <td>{e.targetType && `${e.targetType} ${e.targetId?.slice(0, 8) ?? ''}`}</td>
              <td>
                {/* Text, never HTML: details can contain attacker-chosen strings. */}
                <code>{JSON.stringify(e.details)}</code>
              </td>
              <td title={`prev ${e.prevHash}\nthis ${e.entryHash}`}>
                <code>{short(e.entryHash)}</code>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {more && (
        <button type="button" onClick={() => void loadMore()}>
          Load more
        </button>
      )}
    </section>
  )
}
