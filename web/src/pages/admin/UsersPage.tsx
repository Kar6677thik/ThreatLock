import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { ApiError } from '../../api/client'
import { ROLES, type AdminUserView } from '../../api/types'
import { isOwner, isSecurityAdmin } from '../../auth/roles'
import { useAuth } from '../../auth/useAuth'

/** The org's users: add people; security admins can sign someone out everywhere and unlock locked accounts. */
export function UsersPage() {
  const { call, session } = useAuth()
  const [users, setUsers] = useState<AdminUserView[]>([])
  const [form, setForm] = useState({ email: '', displayName: '', password: '', roles: [] as string[] })
  const [messages, setMessages] = useState<string[]>([])

  const load = useCallback(() => call<AdminUserView[]>('/api/admin/users').then(setUsers), [call])
  useEffect(() => {
    void load()
  }, [load])

  const me = session!.user
  // Everyone is a member automatically; only owners may grant more (privilege-escalation guard, enforced by the API too).
  const grantable = isOwner(me) ? ROLES.filter((r) => r !== 'member') : []

  async function create(event: FormEvent) {
    event.preventDefault()
    try {
      await call('/api/admin/users', { method: 'POST', body: form })
      setForm({ email: '', displayName: '', password: '', roles: [] })
      setMessages([`Added ${form.displayName}.`])
      await load()
    } catch (e) {
      setMessages(e instanceof ApiError ? e.messages : [String(e)])
    }
  }

  async function revoke(user: AdminUserView) {
    const result = await call<{ revokedSessions: number }>(`/api/admin/users/${user.id}/revoke-sessions`, { method: 'POST' })
    setMessages([`Signed ${user.displayName} out of ${result.revokedSessions} session(s).`])
  }

  async function unlock(user: AdminUserView) {
    await call(`/api/admin/users/${user.id}/unlock`, { method: 'POST' })
    setMessages([`Unlocked ${user.displayName}. They can sign in again.`])
    await load()
  }

  return (
    <section>
      <h2>Users</h2>
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Email</th>
            <th>Roles</th>
            <th>Status</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {users.map((u) => (
            <tr key={u.id}>
              <td>{u.displayName}</td>
              <td>{u.email}</td>
              <td>{u.roles.join(', ')}</td>
              <td>
                {u.securityLockedAt ? (
                  <span className="locked" title={`Locked ${new Date(u.securityLockedAt).toLocaleString()}`}>
                    Locked ({u.securityLockedReason})
                  </span>
                ) : (
                  'Active'
                )}
              </td>
              <td className="row">
                {isSecurityAdmin(me) && (
                  <button type="button" onClick={() => void revoke(u)}>
                    Sign out everywhere
                  </button>
                )}
                {isSecurityAdmin(me) && u.securityLockedAt && (
                  <button type="button" onClick={() => void unlock(u)}>
                    Unlock
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <h3>Add a user</h3>
      <form onSubmit={create} className="stack">
        <label>
          Name
          <input value={form.displayName} onChange={(e) => setForm({ ...form, displayName: e.target.value })} required />
        </label>
        <label>
          Email
          <input type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} required />
        </label>
        <label>
          Initial password
          <input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} required minLength={12} autoComplete="new-password" />
        </label>
        {grantable.length > 0 && (
          <fieldset>
            <legend>Extra roles (owners only)</legend>
            {grantable.map((role) => (
              <label key={role} className="row">
                <input
                  type="checkbox"
                  checked={form.roles.includes(role)}
                  onChange={() => setForm({ ...form, roles: form.roles.includes(role) ? form.roles.filter((r) => r !== role) : [...form.roles, role] })}
                />
                {role}
              </label>
            ))}
          </fieldset>
        )}
        <button type="submit">Add user</button>
      </form>
      {messages.length > 0 && (
        <ul role="status">
          {messages.map((m) => (
            <li key={m}>{m}</li>
          ))}
        </ul>
      )}
    </section>
  )
}
