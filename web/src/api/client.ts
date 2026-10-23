// One place that performs authenticated HTTP calls. Components never call fetch directly, so
// auth headers and error handling stay consistent. In M3 this is where "on 401, refresh the
// access token once, then retry" will live (SPEC §14).

/** RFC 9457 problem details, as returned by the API on errors. */
export interface Problem {
  title?: string
  detail?: string
  status?: number
  errors?: Record<string, string[]>
}

export class ApiError extends Error {
  readonly status: number
  readonly problem: Problem

  constructor(status: number, problem: Problem) {
    super(problem.detail ?? problem.title ?? `Request failed (${status})`)
    this.name = 'ApiError'
    this.status = status
    this.problem = problem
  }

  /** Every validation message, flattened, for showing under a form. */
  get messages(): string[] {
    return this.problem.errors ? Object.values(this.problem.errors).flat() : [this.message]
  }
}

export interface RequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE'
  body?: unknown
  token?: string
  signal?: AbortSignal
}

/** Sends a request and returns the raw response, throwing ApiError for non-2xx answers. */
export async function send(path: string, options: RequestOptions = {}): Promise<Response> {
  const headers: Record<string, string> = {}
  if (options.body !== undefined) headers['Content-Type'] = 'application/json'
  if (options.token) headers.Authorization = `Bearer ${options.token}`

  const response = await fetch(path, {
    method: options.method ?? 'GET',
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
    signal: options.signal,
  })

  if (!response.ok) {
    const problem = (await response.json().catch(() => ({}))) as Problem
    throw new ApiError(response.status, problem)
  }
  return response
}

/** Like send, but parses a JSON body (or returns undefined for 204 No Content). */
export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const response = await send(path, options)
  return (response.status === 204 ? undefined : await response.json()) as T
}
