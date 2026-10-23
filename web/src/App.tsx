import { useState } from 'react'
import { AuthProvider } from './auth/AuthContext'
import { useAuth } from './auth/useAuth'
import { LoginPage } from './pages/LoginPage'
import { NotesPage } from './pages/NotesPage'
import { SessionsPage } from './pages/SessionsPage'

type Tab = 'notes' | 'sessions'

// No router yet: a couple of screens, chosen by session state and a tab. Admin screens (M5) bring routing.
function Shell() {
  const { status, session, logout } = useAuth()
  const [tab, setTab] = useState<Tab>('notes')

  if (status === 'restoring') return <main aria-busy="true">Loading…</main>

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
      {session ? (
        <>
          <nav className="row">
            <button type="button" className="link" aria-current={tab === 'notes'} onClick={() => setTab('notes')}>
              Notes
            </button>
            <button type="button" className="link" aria-current={tab === 'sessions'} onClick={() => setTab('sessions')}>
              My sessions
            </button>
          </nav>
          {tab === 'notes' ? <NotesPage /> : <SessionsPage />}
        </>
      ) : (
        <LoginPage />
      )}
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
