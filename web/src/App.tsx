import { BrowserRouter, Navigate, NavLink, Route, Routes } from 'react-router'
import { AuthProvider } from './auth/AuthContext'
import { isAdmin, isSecurityAdmin } from './auth/roles'
import { useAuth } from './auth/useAuth'
import { LoginPage } from './pages/LoginPage'
import { NotesPage } from './pages/NotesPage'
import { SessionsPage } from './pages/SessionsPage'
import { AnomaliesPage } from './pages/admin/AnomaliesPage'
import { AnomalyDetailPage } from './pages/admin/AnomalyDetailPage'
import { PolicyPage } from './pages/admin/PolicyPage'
import { UsersPage } from './pages/admin/UsersPage'

/**
 * The app shell. Routes for screens you can't use simply don't exist for you; the API enforces
 * the same rules anyway, so hiding links is about clarity, not security.
 */
function Shell() {
  const { status, session, logout } = useAuth()

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
        {isAdmin(user) && <NavLink to="/admin/anomalies">Anomalies</NavLink>}
        {isAdmin(user) && <NavLink to="/admin/users">Users</NavLink>}
        {isSecurityAdmin(user) && <NavLink to="/admin/policy">Policy</NavLink>}
      </nav>
      <Routes>
        <Route path="/notes" element={<NotesPage />} />
        <Route path="/sessions" element={<SessionsPage />} />
        {isAdmin(user) && <Route path="/admin/anomalies" element={<AnomaliesPage />} />}
        {isAdmin(user) && <Route path="/admin/anomalies/:id" element={<AnomalyDetailPage />} />}
        {isAdmin(user) && <Route path="/admin/users" element={<UsersPage />} />}
        {isSecurityAdmin(user) && <Route path="/admin/policy" element={<PolicyPage />} />}
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
