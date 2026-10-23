import { createContext, useContext } from 'react'
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

export interface AuthValue {
  session: Session | null
  login: (email: string, password: string) => Promise<void>
  register: (input: RegisterInput) => Promise<void>
  logout: () => Promise<void>
  /** Call when the API answers 401: the token is no longer accepted. */
  expire: () => void
}

// Kept apart from AuthProvider so that file exports only a component (React fast refresh).
export const AuthContext = createContext<AuthValue | null>(null)

export function useAuth(): AuthValue {
  const value = useContext(AuthContext)
  if (!value) throw new Error('useAuth must be used inside <AuthProvider>')
  return value
}
