import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, request } from './client'

function respond(body: unknown, status: number) {
  const fetchMock = vi.fn((_url: string, _init?: RequestInit) =>
    Promise.resolve(new Response(body === undefined ? null : JSON.stringify(body), { status })),
  )
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

describe('request', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('sends the bearer token and JSON body', async () => {
    const fetchMock = respond({ ok: true }, 200)

    await request('/api/notes', { method: 'POST', body: { title: 'x' }, token: 'abc' })

    const [, init] = fetchMock.mock.calls[0]
    const headers = (init?.headers ?? {}) as Record<string, string>
    expect(headers).toMatchObject({ 'Content-Type': 'application/json', Authorization: 'Bearer abc' })
    expect(headers['X-Device-Id']).toMatch(/^[0-9a-f-]{36}$/)
    expect(init?.body).toBe('{"title":"x"}')
  })

  it('turns problem details into an ApiError with flattened validation messages', async () => {
    respond({ status: 400, errors: { Title: ['Title is required.'], Body: ['Too long.'] } }, 400)

    const error = await request('/api/notes').catch((e: unknown) => e)

    expect(error).toBeInstanceOf(ApiError)
    expect((error as ApiError).status).toBe(400)
    expect((error as ApiError).messages).toEqual(['Title is required.', 'Too long.'])
  })

  it('uses the problem detail as the message', async () => {
    respond({ status: 401, detail: 'Invalid email or password.' }, 401)

    await expect(request('/api/auth/login')).rejects.toThrow('Invalid email or password.')
  })

  it('returns undefined for 204 No Content', async () => {
    respond(undefined, 204)

    await expect(request('/api/auth/logout', { method: 'POST' })).resolves.toBeUndefined()
  })
})
