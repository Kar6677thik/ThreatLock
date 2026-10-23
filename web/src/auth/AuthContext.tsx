import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { ApiError, request, send } from '../api/client'
import type { LoginResponse } from '../api/types'
import { AuthContext, type AuthValue, type CallOptions, type RegisterInput, type Session } from './useAuth'

const SIGNED_OUT_MESSAGE = 'You were signed out. Please sign in again.'

/**
 * Owns the session (SPEC §6, §14).
 *
 * - The access token lives in React state only (memory), never localStorage, so an XSS bug
 *   can't read a long-lived credential out of storage.
 * - The refresh token is an HttpOnly cookie the browser holds; JavaScript never sees it. On page
 *   load we call /api/auth/refresh to turn that cookie back into an access token, so a reload
 *   no longer signs you out.
 * - When a call gets 401 we refresh once and retry. All callers share one in-flight refresh,
 *   so five failing requests trigger one refresh, not five racing ones.
 */
export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(null)
  const [status, setStatus] = useState<AuthValue['status']>('restoring')
  const [signedOutReason, setSignedOutReason] = useState<string | null>(null)

  // Refs give the async helpers the *current* values without re-creating them on every render.
  const tokenRef = useRef<string | null>(null)
  const refreshing = useRef<Promise<string | null> | null>(null)

  const accept = useCallback((r: LoginResponse) => {
    tokenRef.current = r.accessToken
    setSession({ token: r.accessToken, expiresAt: r.expiresAt, user: r.user })
    setStatus('signed-in')
    setSignedOutReason(null)
  }, [])

  const drop = useCallback((reason: string | null) => {
    tokenRef.current = null
    setSession(null)
    setStatus('signed-out')
    setSignedOutReason(reason)
  }, [])

  /** Swaps the refresh cookie for a new access token. Returns null if the session is gone. */
  const refresh = useCallback((): Promise<string | null> => {
    refreshing.current ??= (async () => {
      const attempt = () =>
        request<LoginResponse>('/api/auth/refresh', { method: 'POST', headers: { 'X-Requested-With': 'threatlock' } })
      try {
        let response: LoginResponse
        try {
          response = await attempt()
        } catch (error) {
          // 409: another tab refreshed with the same cookie a moment ago. The browser now holds
          // the newer cookie, so a short pause and one retry succeeds.
          if (!(error instanceof ApiError && error.status === 409)) throw error
          await new Promise((resolve) => setTimeout(resolve, 300))
          response = await attempt()
        }
        accept(response)
        return response.accessToken
      } catch {
        return null
      } finally {
        refreshing.current = null
      }
    })()
    return refreshing.current
  }, [accept])

  // On first load: is there a session to restore from the refresh cookie?
  useEffect(() => {
    void refresh().then((token) => {
      if (!token) drop(null)
    })
  }, [refresh, drop])

  const callRaw = useCallback(
    async (path: string, options: CallOptions = {}): Promise<Response> => {
      try {
        return await send(path, { ...options, token: tokenRef.current ?? undefined })
      } catch (error) {
        if (!(error instanceof ApiError && error.status === 401)) throw error
        // The access token expired (every 5 minutes) or the session was revoked. Refresh tells
        // the two apart: it succeeds in the first case and fails in the second.
        const token = await refresh()
        if (!token) {
          drop(SIGNED_OUT_MESSAGE)
          throw error
        }
        return await send(path, { ...options, token })
      }
    },
    [refresh, drop],
  )

  const call = useCallback(
    async <T,>(path: string, options: CallOptions = {}): Promise<T> => {
      const response = await callRaw(path, options)
      return (response.status === 204 ? undefined : await response.json()) as T
    },
    [callRaw],
  )

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
    // Since M3 this really ends the session on the server: the token and cookie stop working.
    await callRaw('/api/auth/logout', { method: 'POST' }).catch(() => undefined)
    drop(null)
  }, [callRaw, drop])

  const value = useMemo<AuthValue>(
    () => ({ status, session, signedOutReason, login, register, logout, call, callRaw }),
    [status, session, signedOutReason, login, register, logout, call, callRaw],
  )
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
