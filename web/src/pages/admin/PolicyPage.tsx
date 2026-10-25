import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { ApiError } from '../../api/client'
import {
  DETECTORS,
  MODES,
  ROLES,
  SEVERITIES,
  type AdminUserView,
  type DetectorPolicy,
  type PolicyVersionView,
  type PolicyView,
  type SecurityPolicy,
} from '../../api/types'
import { useAuth } from '../../auth/useAuth'

const THRESHOLDS: Record<string, { key: string; label: string }[]> = {
  impossible_travel: [
    { key: 'maxSpeedKmh', label: 'Max speed (km/h)' },
    { key: 'minDistanceKm', label: 'Ignore distances under (km)' },
  ],
  scraping: [
    { key: 'k', label: 'Standard deviations above normal (k)' },
    { key: 'floorPerMinute', label: 'Never flag below (reads/min)' },
    { key: 'minActiveMinutes', label: 'Trust a baseline after (active minutes)' },
  ],
  new_device_export: [
    { key: 'windowMinutes', label: 'Window after first login (min)' },
    { key: 'bulkReadThreshold', label: 'Bulk read: distinct notes' },
  ],
}

function toggle(list: string[], value: string) {
  return list.includes(value) ? list.filter((v) => v !== value) : [...list, value]
}

/**
 * Edits the org's security policy (SPEC §9). The form keeps the version it loaded and sends it
 * back as expectedVersion; if someone saved in between, the API answers 409 and we say so
 * instead of overwriting their change.
 */
export function PolicyPage() {
  const { call } = useAuth()
  const [loaded, setLoaded] = useState<PolicyView | null>(null)
  const [draft, setDraft] = useState<SecurityPolicy | null>(null)
  const [networks, setNetworks] = useState('')
  const [users, setUsers] = useState<AdminUserView[]>([])
  const [versions, setVersions] = useState<PolicyVersionView[]>([])
  const [errors, setErrors] = useState<string[]>([])
  const [message, setMessage] = useState<string | null>(null)
  const [conflict, setConflict] = useState(false)

  // Fetching (no state) and applying (state) are separate, so the effect below only sets state
  // from a resolved promise, never synchronously during the effect.
  const fetchAll = useCallback(
    () =>
      Promise.all([
        call<PolicyView>('/api/admin/policy'),
        call<AdminUserView[]>('/api/admin/users'),
        call<PolicyVersionView[]>('/api/admin/policy/versions'),
      ]),
    [call],
  )

  const apply = useCallback(([view, team, history]: [PolicyView, AdminUserView[], PolicyVersionView[]]) => {
    setLoaded(view)
    setDraft(view.policy)
    setNetworks(view.policy.trustedNetworks.join('\n'))
    setUsers(team)
    setVersions(history)
    setConflict(false)
  }, [])

  const load = useCallback(async () => apply(await fetchAll()), [fetchAll, apply])

  useEffect(() => {
    fetchAll()
      .then(apply)
      .catch((e: unknown) => setErrors([String(e)]))
  }, [fetchAll, apply])

  if (!draft || !loaded) return errors.length ? <p role="alert">{errors[0]}</p> : <p>Loading…</p>

  const detector = (id: string): DetectorPolicy => draft.detectors[id] ?? { mode: 'observe', minSeverity: 'low' }
  const setDetector = (id: string, change: Partial<DetectorPolicy>) =>
    setDraft({ ...draft, detectors: { ...draft.detectors, [id]: { ...detector(id), ...change } } })

  async function save(event: FormEvent) {
    event.preventDefault()
    if (!draft || !loaded) return
    setErrors([])
    setMessage(null)
    const policy = { ...draft, trustedNetworks: networks.split('\n').map((n) => n.trim()).filter(Boolean) }
    try {
      const saved = await call<PolicyView>('/api/admin/policy', {
        method: 'PUT',
        body: { expectedVersion: loaded.version, policy },
      })
      setMessage(`Saved as version ${saved.version}. The Worker applies it within seconds.`)
      await load()
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) setConflict(true)
      setErrors(e instanceof ApiError ? e.messages : [String(e)])
    }
  }

  return (
    <section>
      <h2>Security policy</h2>
      <p>
        Version {loaded.version}
        {loaded.updatedBy && ` · last changed by ${loaded.updatedBy} on ${new Date(loaded.updatedAt!).toLocaleString()}`}
        {loaded.version === 0 && ' (defaults: never edited)'}
      </p>

      <form onSubmit={save} className="stack wide">
        <fieldset>
          <legend>Detectors</legend>
          <table>
            <thead>
              <tr>
                <th>Detector</th>
                <th>Mode</th>
                <th>Minimum severity to act</th>
                <th>Thresholds</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(DETECTORS).map(([id, label]) => (
                <tr key={id}>
                  <td>{label}</td>
                  <td>
                    <select aria-label={`${label} mode`} value={detector(id).mode} onChange={(e) => setDetector(id, { mode: e.target.value as DetectorPolicy['mode'] })}>
                      {MODES.map((m) => (
                        <option key={m}>{m}</option>
                      ))}
                    </select>
                  </td>
                  <td>
                    <select aria-label={`${label} minimum severity`} value={detector(id).minSeverity} onChange={(e) => setDetector(id, { minSeverity: e.target.value as DetectorPolicy['minSeverity'] })}>
                      {SEVERITIES.map((s) => (
                        <option key={s}>{s}</option>
                      ))}
                    </select>
                  </td>
                  <td>
                    {(THRESHOLDS[id] ?? []).map(({ key, label: name }) => (
                      <label key={key} className="inline">
                        {name}{' '}
                        <input
                          type="number"
                          value={detector(id).thresholds?.[key] ?? ''}
                          onChange={(e) => setDetector(id, { thresholds: { ...detector(id).thresholds, [key]: Number(e.target.value) } })}
                        />
                      </label>
                    ))}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <small>off: never runs · observe: record only · notify: record and tell admins · respond: also sign the user out everywhere</small>
        </fieldset>

        <label>
          Trusted networks (one per line, e.g. your VPN's egress range 203.0.113.0/24). Anomalies whose addresses are all inside these are suppressed.
          <textarea rows={4} value={networks} onChange={(e) => setNetworks(e.target.value)} />
        </label>

        <fieldset>
          <legend>Excluded users (never acted on, still recorded)</legend>
          {users.map((u) => (
            <label key={u.id} className="row">
              <input type="checkbox" checked={draft.excludedUserIds.includes(u.id)} onChange={() => setDraft({ ...draft, excludedUserIds: toggle(draft.excludedUserIds, u.id) })} />
              {u.displayName} <small>{u.email}</small>
            </label>
          ))}
        </fieldset>

        <fieldset>
          <legend>Roles</legend>
          {ROLES.map((role) => (
            <div key={role} className="row">
              <code>{role}</code>
              <label className="row">
                <input type="checkbox" checked={draft.excludedRoles.includes(role)} onChange={() => setDraft({ ...draft, excludedRoles: toggle(draft.excludedRoles, role) })} />
                exclude
              </label>
              <label className="row">
                <input type="checkbox" checked={draft.notifyRoles.includes(role)} onChange={() => setDraft({ ...draft, notifyRoles: toggle(draft.notifyRoles, role) })} />
                notify
              </label>
            </div>
          ))}
        </fieldset>

        <fieldset>
          <legend>Response (used from M6)</legend>
          <label className="row">
            Action
            <select value={draft.response.action} onChange={(e) => setDraft({ ...draft, response: { ...draft.response, action: e.target.value as SecurityPolicy['response']['action'] } })}>
              <option value="revoke_sessions">revoke sessions</option>
              <option value="revoke_and_lock">revoke sessions and lock the account</option>
            </select>
          </label>
          <label className="row">
            Lock the account at severity
            <select value={draft.response.lockOnSeverity} onChange={(e) => setDraft({ ...draft, response: { ...draft.response, lockOnSeverity: e.target.value as SecurityPolicy['response']['lockOnSeverity'] } })}>
              {SEVERITIES.map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          </label>
        </fieldset>

        {errors.length > 0 && (
          <ul role="alert" className="errors">
            {errors.map((m) => (
              <li key={m}>{m}</li>
            ))}
          </ul>
        )}
        {conflict && (
          <button type="button" onClick={() => void load()}>
            Reload the latest version
          </button>
        )}
        {message && <p role="status">{message}</p>}
        <button type="submit">Save policy</button>
      </form>

      <h3>History</h3>
      <ul>
        {versions.map((v) => (
          <li key={v.version}>
            v{v.version}: {new Date(v.updatedAt).toLocaleString()} by {v.updatedBy ?? 'unknown'}
          </li>
        ))}
        <li>v0: defaults</li>
      </ul>
    </section>
  )
}
