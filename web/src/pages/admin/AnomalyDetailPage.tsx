import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router'
import { ApiError } from '../../api/client'
import { DETECTORS, type AnomalyView, type ResponseJobView } from '../../api/types'
import { useAuth } from '../../auth/useAuth'

/** One anomaly: what was seen, what the policy decided and why, and what the response did. */
export function AnomalyDetailPage() {
  const { id } = useParams()
  const { call } = useAuth()
  const [anomaly, setAnomaly] = useState<AnomalyView | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    call<AnomalyView>(`/api/admin/anomalies/${id}`)
      .then(setAnomaly)
      .catch((e: unknown) => setError(e instanceof ApiError && e.status === 404 ? 'Anomaly not found.' : String(e)))
  }, [call, id])

  if (error) return <p role="alert">{error}</p>
  if (!anomaly) return <p>Loading…</p>

  return (
    <section>
      <p>
        <Link to="/admin/anomalies">← All anomalies</Link>
      </p>
      <h2>{DETECTORS[anomaly.detector] ?? anomaly.detector}</h2>
      <dl className="facts">
        <dt>Severity</dt>
        <dd className={`severity-${anomaly.severity}`}>{anomaly.severity}</dd>
        <dt>User</dt>
        <dd>{anomaly.userName ?? anomaly.userId}</dd>
        <dt>Detected</dt>
        <dd>{new Date(anomaly.detectedAt).toLocaleString()}</dd>
        <dt>Decision</dt>
        <dd>
          <strong>{anomaly.decision ?? 'pending'}</strong> ({anomaly.decisionReason ?? 'no reason recorded'}), judged by policy v
          {anomaly.policyVersion ?? '?'}
        </dd>
        <dt>Events</dt>
        <dd>{anomaly.eventCount}</dd>
        <dt>Session</dt>
        <dd>
          <code>{anomaly.sessionId ?? 'none'}</code>
        </dd>
      </dl>
      <h3>Response</h3>
      {anomaly.response ? (
        <ResponseTimeline job={anomaly.response} revokedSessions={anomaly.revokedSessions ?? 0} />
      ) : (
        <p>None needed: the decision was {anomaly.decision ?? 'not made'}.</p>
      )}
      <h3>Evidence</h3>
      {/* Rendered as text, never as HTML: evidence contains attacker-controlled strings (user agents). */}
      <pre className="evidence">{JSON.stringify(anomaly.evidence, null, 2)}</pre>
    </section>
  )
}

function at(value: string | null) {
  return value ? new Date(value).toLocaleString() : '—'
}

/** The job's steps in order, with when each finished. */
function ResponseTimeline({ job, revokedSessions }: { job: ResponseJobView; revokedSessions: number }) {
  const revokes = job.action !== 'notify'
  return (
    <>
      <p>
        <strong>{job.action}</strong>: {job.status} after {job.attempts} attempt(s)
        {job.lastError && (
          <>
            {' '}
            · last error <code>{job.lastError}</code>
          </>
        )}
      </p>
      <ol className="timeline">
        <li>Job created {at(job.createdAt)}</li>
        {revokes && (
          <li>
            {revokedSessions} session(s) revoked{job.action === 'revoke_and_lock' && ' and account locked'} {at(job.revokedAt)}
          </li>
        )}
        <li>Admins notified {at(job.notifiedAt)}</li>
        <li>Finished {at(job.finishedAt)}</li>
      </ol>
    </>
  )
}
