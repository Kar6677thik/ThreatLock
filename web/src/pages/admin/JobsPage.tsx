import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router'
import { ApiError } from '../../api/client'
import type { JobStatus, ResponseJobView } from '../../api/types'
import { useAuth } from '../../auth/useAuth'

const FILTERS: { value: '' | JobStatus; label: string }[] = [
  { value: '', label: 'Needs attention' },
  { value: 'dead', label: 'Dead' },
  { value: 'pending', label: 'Pending' },
  { value: 'running', label: 'Running' },
  { value: 'succeeded', label: 'Succeeded' },
]

/**
 * Response jobs that failed (SPEC §14 "Jobs"). A dead job has used all five attempts; "Retry"
 * gives it five more. Steps it already finished are not repeated.
 */
export function JobsPage() {
  const { call } = useAuth()
  const [params, setParams] = useSearchParams()
  const status = params.get('status') ?? ''
  const [jobs, setJobs] = useState<ResponseJobView[] | null>(null)
  const [message, setMessage] = useState<string | null>(null)
  const [version, setVersion] = useState(0)

  useEffect(() => {
    call<ResponseJobView[]>(`/api/admin/response-jobs${status ? `?status=${status}` : ''}`).then(setJobs)
  }, [call, status, version])

  async function retry(job: ResponseJobView) {
    try {
      await call(`/api/admin/response-jobs/${job.id}/retry`, { method: 'POST' })
      setMessage('Job queued again.')
    } catch (e) {
      setMessage(e instanceof ApiError ? e.message : String(e))
    }
    setVersion((v) => v + 1)
  }

  return (
    <section>
      <h2>Response jobs</h2>
      <label>
        Show{' '}
        <select value={status} onChange={(e) => setParams(e.target.value ? { status: e.target.value } : {})}>
          {FILTERS.map((f) => (
            <option key={f.value} value={f.value}>
              {f.label}
            </option>
          ))}
        </select>
      </label>
      {message && <p role="status">{message}</p>}
      {!jobs ? (
        <p>Loading…</p>
      ) : jobs.length === 0 ? (
        <p>No jobs here. Responses are running normally.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Created</th>
              <th>Action</th>
              <th>Status</th>
              <th>Attempts</th>
              <th>Last error</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {jobs.map((job) => (
              <tr key={job.id}>
                <td>
                  <Link to={`/admin/anomalies/${job.anomalyId}`}>{new Date(job.createdAt).toLocaleString()}</Link>
                </td>
                <td>{job.action}</td>
                <td>{job.status}</td>
                <td>{job.attempts}</td>
                <td>
                  <code>{job.lastError ?? ''}</code>
                </td>
                <td>
                  {job.status === 'dead' && (
                    <button type="button" onClick={() => void retry(job)}>
                      Retry
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  )
}
