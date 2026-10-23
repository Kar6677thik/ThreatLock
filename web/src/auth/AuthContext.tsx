import { useCallback, useMemo, useState, type ReactNode } from 'react'
import { request, send } from '../api/client'
import type { LoginResponse } from '../api/types'
import { AuthContext, type RegisterInput, type Session } from './useAuth'

/**
 * Holds the access token in React state, i.e. in memory only. Not localStorage: anything an
 * XSS bug injects into the page could read localStorage and walk off with the token (SPEC §6.2).
 * The cost: reloading the page signs you out. M3's HttpOnly refresh cookie fixes that.
 */
export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(null)

  const accept = useCallback((r: LoginResponse) => {
    setSession({ token: r.accessToken, expiresAt: r.expiresAt, user: r.user })
  }, [])

  const login = useCallback(
    async (email: string, password: string) =>
      accept(await request<LoginResponse>('/api/auth/login', { method: 'POST', body: { email, password } })),
    [accept],
  )

  const register = useCallback(
    async (input: RegisterInput) =>
      accept(await request<LoginResponse>('/api/auth/register-org', { method: 'POST', body: input })),
    [accept],
  )

  const logout = useCallback(async () => {
    // In M2 the server has nothing to revoke (Break B1); we tell it anyway, then forget the token.
    if (session) await send('/api/auth/logout', { method: 'POST', token: session.token }).catch(() => undefined)
    setSession(null)
  }, [session])

  const expire = useCallback(() => setSession(null), [])

  const value = useMemo(() => ({ session, login, register, logout, expire }), [session, login, register, logout, expire])
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
