// Shapes of the API's JSON. They mirror the C# records in src/ThreatLock.Api; in a later
// milestone these are generated from the OpenAPI document instead of written by hand (SPEC §13).

export interface UserView {
  id: string
  email: string
  displayName: string
  orgId: string
  orgName: string
  orgSlug: string
  roles: string[]
}

export interface LoginResponse {
  accessToken: string
  expiresAt: string
  user: UserView
}

export interface NoteSummary {
  id: string
  title: string
  shared: boolean
  isOwner: boolean
  ownerName: string
  updatedAt: string
}

export interface NoteView extends NoteSummary {
  body: string
  createdAt: string
}

export interface NoteRequest {
  title: string
  body: string
  shared: boolean
}

export interface SessionView {
  id: string
  createdAt: string
  lastSeenAt: string
  ip: string | null
  deviceId: string | null
  userAgent: string | null
  current: boolean
}

// ---- Admin (M4–M5) ----

export type DetectorMode = 'off' | 'observe' | 'notify' | 'respond'
export type Severity = 'low' | 'medium' | 'high' | 'critical'
export type Decision = 'suppressed' | 'observed' | 'notified' | 'responded'

export interface AnomalyView {
  id: string
  detector: string
  severity: Severity
  userId: string
  userName: string | null
  sessionId: string | null
  detectedAt: string
  eventCount: number
  eventIds: string[]
  evidence: Record<string, unknown>
  decision: Decision | null
  decisionReason: string | null
  policyVersion: number | null
}

export interface DetectorPolicy {
  mode: DetectorMode
  minSeverity: Severity
  thresholds?: Record<string, number> | null
}

export interface SecurityPolicy {
  trustedNetworks: string[]
  excludedUserIds: string[]
  excludedRoles: string[]
  notifyRoles: string[]
  detectors: Record<string, DetectorPolicy>
  response: { action: 'revoke_sessions' | 'revoke_and_lock'; lockOnSeverity: Severity }
}

export interface PolicyView {
  version: number
  updatedAt: string | null
  updatedBy: string | null
  policy: SecurityPolicy
}

export interface PolicyVersionView {
  version: number
  updatedAt: string
  updatedBy: string | null
}

export interface AdminUserView {
  id: string
  email: string
  displayName: string
  roles: string[]
  createdAt: string
}

export const ROLES = ['member', 'admin', 'security_admin', 'owner'] as const
export const DETECTORS: Record<string, string> = { tor: 'Tor exit node (D1)', impossible_travel: 'Impossible travel (D2)' }
export const SEVERITIES: Severity[] = ['low', 'medium', 'high', 'critical']
export const MODES: DetectorMode[] = ['off', 'observe', 'notify', 'respond']
