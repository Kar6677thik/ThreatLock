import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router'
import { ApiError } from '../../api/client'
import { DETECTORS, type AnomalyView } from '../../api/types'
import { useAuth } from '../../auth/useAuth'

const DECISIONS = ['responded', 'notified', 'observed', 'suppressed']

/** Recent anomalies with filters kept in the URL, so a filtered view can be bookmarked or shared. */
export function AnomaliesPage() {
  const { call } = useAuth()
  const [params, setParams] = useSearchParams()
  const [anomalies, setAnomalies] = useState<AnomalyView[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const detector = params.get('detector') ?? ''
  const decision = params.get('decision') ?? ''

  useEffect(() => {
    const query = new URLSearchParams()
    if (detector) query.set('detector', detector)
    if (decision) query.set('decision', decision)
    const controller = new AbortController()
    call<AnomalyView[]>(`/api/admin/anomalies?${query}`, { signal: controller.signal })
      .then(setAnomalies)
      .catch((e: unknown) => controller.signal.aborted || setError(e instanceof ApiError ? e.message : String(e)))
    return () => controller.abort()
  }, [call, detector, decision])

  function filter(name: string, value: string) {
    const next = new URLSearchParams(params)
    if (value) next.set(name, value)
    else next.delete(name)
    setParams(next)
  }

  return (
    <section>
      <h2>Anomalies</h2>
      <div className="row">
        <label>
          Detector{' '}
          <select value={detector} onChange={(e) => filter('detector', e.target.value)}>
            <option value="">all</option>
            {Object.entries(DETECTORS).map(([id, label]) => (
              <option key={id} value={id}>
                {label}
              </option>
            ))}
          </select>
        </label>
        <label>
          Decision{' '}
          <select value={decision} onChange={(e) => filter('decision', e.target.value)}>
            <option value="">all</option>
            {DECISIONS.map((d) => (
              <option key={d}>{d}</option>
            ))}
          </select>
        </label>
      </div>
      {error && <p role="alert">{error}</p>}
      {anomalies === null ? (
        <p>Loading…</p>
      ) : anomalies.length === 0 ? (
        <p>No anomalies match.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Detected</th>
              <th>Detector</th>
              <th>Severity</th>
              <th>User</th>
              <th>Decision</th>
              <th>Events</th>
            </tr>
          </thead>
          <tbody>
            {anomalies.map((a) => (
              <tr key={a.id}>
                <td>
                  <Link to={`/admin/anomalies/${a.id}`}>{new Date(a.detectedAt).toLocaleString()}</Link>
                </td>
                <td>{DETECTORS[a.detector] ?? a.detector}</td>
                <td className={`severity-${a.severity}`}>{a.severity}</td>
                <td>{a.userName ?? a.userId}</td>
                <td title={a.decisionReason ?? ''}>{a.decision ?? 'pending'}</td>
                <td>{a.eventCount}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  )
}
