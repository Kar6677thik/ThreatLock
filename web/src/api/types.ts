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

// ---- Admin (M4–M6) ----

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
  respondedAt?: string | null
  /** Only on the detail endpoint: the response job, if the decision needed one (M6). */
  response?: ResponseJobView | null
  revokedSessions?: number
}

export type JobStatus = 'pending' | 'running' | 'succeeded' | 'dead'

export interface ResponseJobView {
  id: string
  anomalyId: string
  userId: string
  action: 'notify' | 'revoke_sessions' | 'revoke_and_lock'
  status: JobStatus
  attempts: number
  lastError: string | null
  createdAt: string
  nextAttemptAt: string
  revokedAt: string | null
  notifiedAt: string | null
  finishedAt: string | null
}

export interface NotificationView {
  id: string
  title: string
  anomalyId: string
  lastAnomalyId: string
  subjectUserId: string
  /** Anomalies about the same user grouped into this one entry. */
  count: number
  createdAt: string
  updatedAt: string
  readAt: string | null
}

export interface Inbox {
  unread: number
  items: NotificationView[]
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
  securityLockedAt?: string | null
  securityLockedReason?: string | null
}

// ---- Audit (M7) ----

export interface AuditEntryView {
  seq: number
  occurredAt: string
  actorType: 'user' | 'admin' | 'system'
  actorId: string | null
  actorName: string | null
  action: string
  targetType: string | null
  targetId: string | null
  anomalyId: string | null
  details: Record<string, unknown>
  idempotencyKey: string | null
  prevHash: string
  entryHash: string
}

export interface VerifyResult {
  ok: boolean
  entries: number
  head: string | null
  firstBrokenSeq?: number | null
  reason?: 'hash_mismatch' | 'chain_break' | 'seq_gap' | 'anchor_mismatch' | null
}

export const ROLES = ['member', 'admin', 'security_admin', 'owner'] as const
export const DETECTORS: Record<string, string> = {
  tor: 'Tor exit node (D1)',
  impossible_travel: 'Impossible travel (D2)',
  scraping: 'Scraping rate (D3)',
  new_device_export: 'New device + export (D4)',
  session_hijack: 'Session hijack (D5)',
}
export const SEVERITIES: Severity[] = ['low', 'medium', 'high', 'critical']
export const MODES: DetectorMode[] = ['off', 'observe', 'notify', 'respond']
