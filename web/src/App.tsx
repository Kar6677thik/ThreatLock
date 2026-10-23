import { AuthProvider } from './auth/AuthContext'
import { useAuth } from './auth/useAuth'
import { LoginPage } from './pages/LoginPage'
import { NotesPage } from './pages/NotesPage'

// No router yet: two screens, chosen by whether we hold a session. Admin screens (M5) bring routing.
function Shell() {
  const { session, logout } = useAuth()

  return (
    <main>
      <header className="row spread">
        <h1>ThreatLock</h1>
        {session && (
          <div className="row">
            <span>
              {session.user.displayName} · {session.user.orgName} <small>({session.user.roles.join(', ')})</small>
            </span>
            <button type="button" onClick={logout}>
              Sign out
            </button>
          </div>
        )}
      </header>
      {session ? <NotesPage token={session.token} /> : <LoginPage />}
    </main>
  )
}

export default function App() {
  return (
    <AuthProvider>
      <Shell />
    </AuthProvider>
  )
}
