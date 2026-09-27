import { client as generatedClient } from '@/api/generated/client.gen'
import type { Client, Config } from '@/api/generated/client'
import { getValidRequestBody } from '@/api/generated/core/utils.gen'

/** Error thrown for every non-2xx console API response (`{ "error": string }` payloads). */
export class ApiError extends Error {
  status: number
  payload: unknown

  constructor(message: string, status: number, payload?: unknown) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.payload = payload
  }
}

/** Dispatched on `window` when a request outside of `/api/auth/` is rejected with 401. */
export const UNAUTHORIZED_EVENT = 'maxio:unauthorized'

export function toApiError(payload: unknown, status: number): ApiError {
  const message =
    payload && typeof payload === 'object' && 'error' in payload && typeof payload.error === 'string'
      ? payload.error
      : `Request failed (${status})`
  return new ApiError(message, status, payload)
}

// Routes whose trailing `{key}` is a `{*key}` wildcard on the server: the key keeps its `/` separators.
const OBJECT_KEY_ROUTE =
  /^(\/api\/buckets\/[^/]+\/(?:objects|upload|download|presign|versions\/[^/]+\/(?:objects|download))\/)(.+)$/

/**
 * hey-api encodes path params with `encodeURIComponent`, which turns the `/` inside object keys into `%2F`.
 * Restores the separators in the key part of object routes (other characters stay encoded; a literal `%` in a key
 * is `%25`, so `%2F` can only come from a `/`).
 */
export function restoreObjectKeySlashes(pathname: string): string {
  const match = OBJECT_KEY_ROUTE.exec(pathname)
  if (!match) return pathname
  return match[1] + match[2].replace(/%2F/gi, '/')
}

interface ApiClientOptions {
  fetch?: typeof globalThis.fetch
  onUnauthorized?: () => void
}

/** Applies MaxIO defaults and interceptors to a generated hey-api client. */
export function configureApiClient(client: Client, options: ApiClientOptions = {}): Client {
  const config: Config = {
    baseUrl: globalThis.location?.origin ?? 'http://localhost',
    credentials: 'same-origin',
  }
  if (options.fetch) config.fetch = options.fetch
  client.setConfig(config)

  client.interceptors.request.use((request, opts) => {
    const url = new URL(request.url)
    const pathname = restoreObjectKeySlashes(url.pathname)
    if (pathname === url.pathname) return request
    url.pathname = pathname
    // Rebuild from the original body (e.g. the `File` of an upload) so it is still sent as-is, not as a stream.
    return new Request(url, {
      method: request.method,
      headers: request.headers,
      body: request.body === null ? null : (getValidRequestBody(opts) as BodyInit | null | undefined),
      credentials: request.credentials,
      redirect: request.redirect,
      signal: request.signal,
    })
  })

  client.interceptors.error.use((error, response, request) => {
    // Network failures have no response: keep the original error (callers show "Failed to connect").
    if (!response) return error
    if (response.status === 401 && request && !new URL(request.url).pathname.startsWith('/api/auth/')) {
      options.onUnauthorized?.()
    }
    return toApiError(error, response.status)
  })

  return client
}

export const apiClient = configureApiClient(generatedClient, {
  onUnauthorized: () => window.dispatchEvent(new Event(UNAUTHORIZED_EVENT)),
})
