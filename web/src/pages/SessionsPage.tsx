import { useCallback, useEffect, useState } from 'react'
import { ApiError } from '../api/client'
import type { SessionView } from '../api/types'
import { useAuth } from '../auth/useAuth'

/** "Where am I signed in?" with a sign-out button per device (SPEC §14). */
export function SessionsPage() {
  const { call } = useAuth()
  const [sessions, setSessions] = useState<SessionView[]>([])
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(
    () =>
      call<SessionView[]>('/api/me/sessions')
        .then(setSessions)
        .catch((e: unknown) => setError(e instanceof ApiError ? e.message : String(e))),
    [call],
  )

  useEffect(() => {
    void load()
  }, [load])

  async function signOut(id: string) {
    await call(`/api/me/sessions/${id}`, { method: 'DELETE' })
    await load()
  }

  return (
    <section>
      <h2>Where you're signed in</h2>
      {error && <p role="alert">{error}</p>}
      <table>
        <thead>
          <tr>
            <th>Device</th>
            <th>IP</th>
            <th>Signed in</th>
            <th>Last seen</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {sessions.map((s) => (
            <tr key={s.id}>
              <td title={s.userAgent ?? ''}>
                {s.deviceId ? s.deviceId.slice(0, 8) : 'unknown'} {s.current && <strong>(this browser)</strong>}
              </td>
              <td>{s.ip ?? 'unknown'}</td>
              <td>{new Date(s.createdAt).toLocaleString()}</td>
              <td>{new Date(s.lastSeenAt).toLocaleString()}</td>
              <td>
                {!s.current && (
                  <button type="button" onClick={() => signOut(s.id)}>
                    Sign out
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  )
}
