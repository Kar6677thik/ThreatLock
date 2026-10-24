import type { UserView } from '../api/types'

// Mirrors the API's authorization policies (src/ThreatLock.Api/Auth/Policies.cs). The UI uses
// these only to hide what you can't use; the API enforces them regardless.
export const isAdmin = (u: UserView) => u.roles.some((r) => r === 'admin' || r === 'security_admin' || r === 'owner')
export const isSecurityAdmin = (u: UserView) => u.roles.some((r) => r === 'security_admin' || r === 'owner')
export const isOwner = (u: UserView) => u.roles.includes('owner')
