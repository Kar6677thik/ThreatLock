import { useState, type FormEvent } from 'react'
import { ApiError } from '../api/client'
import { useAuth } from '../auth/useAuth'
import { SystemStatus } from '../components/SystemStatus'

type Mode = 'login' | 'register'

export function LoginPage() {
  const { login, register } = useAuth()
  const [mode, setMode] = useState<Mode>('login')
  const [orgName, setOrgName] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [errors, setErrors] = useState<string[]>([])
  const [busy, setBusy] = useState(false)

  async function submit(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setErrors([])
    try {
      if (mode === 'login') await login(email, password)
      else await register({ orgName, displayName, email, password })
    } catch (error) {
      setErrors(error instanceof ApiError ? error.messages : ['Could not reach the server.'])
    } finally {
      setBusy(false)
    }
  }

  return (
    <section>
      <h2>{mode === 'login' ? 'Sign in' : 'Create an organisation'}</h2>
      <form onSubmit={submit} className="stack">
        {mode === 'register' && (
          <>
            <label>
              Organisation name
              <input value={orgName} onChange={(e) => setOrgName(e.target.value)} required minLength={2} />
            </label>
            <label>
              Your name
              <input value={displayName} onChange={(e) => setDisplayName(e.target.value)} required />
            </label>
          </>
        )}
        <label>
          Email
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoComplete="username" />
        </label>
        <label>
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            minLength={mode === 'register' ? 12 : undefined}
            autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
          />
        </label>
        {errors.length > 0 && (
          <ul role="alert" className="errors">
            {errors.map((message) => (
              <li key={message}>{message}</li>
            ))}
          </ul>
        )}
        <button type="submit" disabled={busy}>
          {mode === 'login' ? 'Sign in' : 'Create organisation'}
        </button>
      </form>
      <p>
        {mode === 'login' ? 'New here? ' : 'Already have an account? '}
        <button type="button" className="link" onClick={() => setMode(mode === 'login' ? 'register' : 'login')}>
          {mode === 'login' ? 'Create an organisation' : 'Sign in'}
        </button>
      </p>
      <hr />
      <SystemStatus />
    </section>
  )
}
