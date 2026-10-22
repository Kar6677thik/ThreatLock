// Calls to the API's system endpoints. All HTTP lives in src/api so components never build URLs
// themselves; in M3 this folder gains the wrapper that refreshes access tokens (SPEC §14).

export interface AppInfo {
  name: string
  version: string
  environment: string
}

export interface Readiness {
  status: 'Healthy' | 'Degraded' | 'Unhealthy'
  checks: Record<string, string>
}

export async function getInfo(signal?: AbortSignal): Promise<AppInfo> {
  const response = await fetch('/api/info', { signal })
  if (!response.ok) throw new Error(`GET /api/info failed: ${response.status}`)
  return (await response.json()) as AppInfo
}

// /readyz returns 503 *with* a JSON body when a dependency is down, so a non-2xx status is
// still a valid answer here, not an error.
export async function getReadiness(signal?: AbortSignal): Promise<Readiness> {
  const response = await fetch('/readyz', { signal })
  return (await response.json()) as Readiness
}
