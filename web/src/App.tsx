import { useEffect, useState } from 'react'
import { BrowserRouter, Navigate, NavLink, Route, Routes } from 'react-router'
import type { Inbox } from './api/types'
import { AuthProvider } from './auth/AuthContext'
import { isAdmin, isSecurityAdmin } from './auth/roles'
import { useAuth } from './auth/useAuth'
import { LoginPage } from './pages/LoginPage'
import { NotesPage } from './pages/NotesPage'
import { SessionsPage } from './pages/SessionsPage'
import { AnomaliesPage } from './pages/admin/AnomaliesPage'
import { AnomalyDetailPage } from './pages/admin/AnomalyDetailPage'
import { AuditPage } from './pages/admin/AuditPage'
import { JobsPage } from './pages/admin/JobsPage'
import { NotificationsPage } from './pages/admin/NotificationsPage'
import { PolicyPage } from './pages/admin/PolicyPage'
import { UsersPage } from './pages/admin/UsersPage'

/** How often the unread badge checks for new notifications. */
const INBOX_POLL_MS = 30_000

/** "Notifications (3)": polls the unread count; `version` forces a re-check after reading. */
function InboxLink({ version }: { version: number }) {
  const { call } = useAuth()
  const [unread, setUnread] = useState(0)

  useEffect(() => {
    const check = () => {
      call<Inbox>('/api/admin/notifications?unreadOnly=true')
        .then((inbox) => setUnread(inbox.unread))
        .catch(() => {})
    }
    check()
    const timer = setInterval(check, INBOX_POLL_MS)
    return () => clearInterval(timer)
  }, [call, version])

  return (
    <NavLink to="/admin/notifications">
      Notifications{unread > 0 && <span className="badge" aria-label={`${unread} unread`}>{unread}</span>}
    </NavLink>
  )
}

/**
 * The app shell. Routes for screens you can't use simply don't exist for you; the API enforces
 * the same rules anyway, so hiding links is about clarity, not security.
 */
function Shell() {
  const { status, session, logout } = useAuth()
  const [inboxVersion, setInboxVersion] = useState(0)

  if (status === 'restoring') return <main aria-busy="true">Loading…</main>
  if (!session) {
    return (
      <main>
        <h1>ThreatLock</h1>
        <LoginPage />
      </main>
    )
  }

  const user = session.user
  return (
    <main>
      <header className="row spread">
        <h1>ThreatLock</h1>
        <div className="row">
          <span>
            {user.displayName} · {user.orgName} <small>({user.roles.join(', ')})</small>
          </span>
          <button type="button" onClick={logout}>
            Sign out
          </button>
        </div>
      </header>
      <nav className="row" aria-label="Main">
        <NavLink to="/notes">Notes</NavLink>
        <NavLink to="/sessions">My sessions</NavLink>
        {isAdmin(user) && <InboxLink version={inboxVersion} />}
        {isAdmin(user) && <NavLink to="/admin/anomalies">Anomalies</NavLink>}
        {isAdmin(user) && <NavLink to="/admin/users">Users</NavLink>}
        {isSecurityAdmin(user) && <NavLink to="/admin/policy">Policy</NavLink>}
        {isSecurityAdmin(user) && <NavLink to="/admin/jobs">Jobs</NavLink>}
        {isSecurityAdmin(user) && <NavLink to="/admin/audit">Audit log</NavLink>}
      </nav>
      <Routes>
        <Route path="/notes" element={<NotesPage />} />
        <Route path="/sessions" element={<SessionsPage />} />
        {isAdmin(user) && <Route path="/admin/anomalies" element={<AnomaliesPage />} />}
        {isAdmin(user) && <Route path="/admin/anomalies/:id" element={<AnomalyDetailPage />} />}
        {isAdmin(user) && <Route path="/admin/users" element={<UsersPage />} />}
        {isAdmin(user) && (
          <Route path="/admin/notifications" element={<NotificationsPage onChange={() => setInboxVersion((v) => v + 1)} />} />
        )}
        {isSecurityAdmin(user) && <Route path="/admin/policy" element={<PolicyPage />} />}
        {isSecurityAdmin(user) && <Route path="/admin/jobs" element={<JobsPage />} />}
        {isSecurityAdmin(user) && <Route path="/admin/audit" element={<AuditPage />} />}
        <Route path="*" element={<Navigate to="/notes" replace />} />
      </Routes>
      <footer>
        <small>
          IP geolocation by <a href="https://db-ip.com">DB-IP</a>
        </small>
      </footer>
    </main>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Shell />
      </AuthProvider>
    </BrowserRouter>
  )
}
