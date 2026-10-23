import { createContext, useContext } from 'react'
import type { RequestOptions } from '../api/client'
import type { UserView } from '../api/types'

export interface Session {
  token: string
  expiresAt: string
  user: UserView
}

export interface RegisterInput {
  orgName: string
  displayName: string
  email: string
  password: string
}

/** Options for an authenticated call: like RequestOptions, minus the token (added for you). */
export type CallOptions = Omit<RequestOptions, 'token'>

export interface AuthValue {
  /** 'restoring' while we check for an existing session on page load. */
  status: 'restoring' | 'signed-in' | 'signed-out'
  session: Session | null
  /** Why the user was signed out, if it wasn't their own choice. */
  signedOutReason: string | null
  login: (email: string, password: string) => Promise<void>
  register: (input: RegisterInput) => Promise<void>
  logout: () => Promise<void>
  /** Authenticated JSON request. On 401 it refreshes the access token once and retries. */
  call: <T>(path: string, options?: CallOptions) => Promise<T>
  /** Same, but returns the raw Response (for downloads). */
  callRaw: (path: string, options?: CallOptions) => Promise<Response>
}

// Kept apart from AuthProvider so that file exports only a component (React fast refresh).
export const AuthContext = createContext<AuthValue | null>(null)

export function useAuth(): AuthValue {
  const value = useContext(AuthContext)
  if (!value) throw new Error('useAuth must be used inside <AuthProvider>')
  return value
}
