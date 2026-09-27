import { describe, expect, mock, test } from 'bun:test'
import { createClient } from '@/api/generated/client'
import * as sdk from '@/api/generated/sdk.gen'
import { ApiError, configureApiClient, restoreObjectKeySlashes, toApiError } from './client'

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function setup(respond: (request: Request) => Response | Promise<Response>) {
  const requests: Request[] = []
  const onUnauthorized = mock(() => {})
  const fetch = (async (input: RequestInfo | URL) => {
    const request = input as Request
    requests.push(request)
    return respond(request)
  }) as typeof globalThis.fetch
  const client = configureApiClient(createClient(), { fetch, onUnauthorized })
  return { client, requests, onUnauthorized }
}

describe('restoreObjectKeySlashes', () => {
  test('restores slashes in the key of object routes only', () => {
    expect(restoreObjectKeySlashes('/api/buckets/b/objects/a%2Fb%2Fc.txt')).toBe('/api/buckets/b/objects/a/b/c.txt')
    expect(restoreObjectKeySlashes('/api/buckets/b/upload/a%2Fb%20c')).toBe('/api/buckets/b/upload/a/b%20c')
    expect(restoreObjectKeySlashes('/api/buckets/b/versions/v%2F1/download/x%2Fy')).toBe(
      '/api/buckets/b/versions/v%2F1/download/x/y',
    )
    expect(restoreObjectKeySlashes('/api/buckets/b/versioning')).toBe('/api/buckets/b/versioning')
  })
})

describe('toApiError', () => {
  test('uses the error field of the payload', () => {
    const error = toApiError({ error: 'Bucket not empty' }, 409)
    expect(error).toBeInstanceOf(ApiError)
    expect(error.message).toBe('Bucket not empty')
    expect(error.status).toBe(409)
  })

  test('falls back to the status code', () => {
    expect(toApiError('oops', 500).message).toBe('Request failed (500)')
  })
})

describe('configureApiClient', () => {
  test('returns data and sends same-origin JSON requests', async () => {
    const { client, requests } = setup(() => json(200, { ok: true }))
    const { data } = await sdk.login({ client, body: { accessKey: 'a', secretKey: 'b' }, throwOnError: true })
    expect(data).toEqual({ ok: true })
    expect(requests[0].method).toBe('POST')
    expect(requests[0].credentials).toBe('same-origin')
    expect(new URL(requests[0].url).pathname).toBe('/api/auth/login')
    expect(await requests[0].json()).toEqual({ accessKey: 'a', secretKey: 'b' })
  })

  test('keeps slashes of object keys while encoding each segment', async () => {
    const { client, requests } = setup(() => json(200, { ok: true }))
    await sdk.deleteObject({ client, path: { bucket: 'media', key: 'photos/my trip/a#1.jpg' }, throwOnError: true })
    expect(new URL(requests[0].url).pathname).toBe('/api/buckets/media/objects/photos/my%20trip/a%231.jpg')
  })

  test('uploads the raw file with its content type', async () => {
    const { client, requests } = setup(() => json(200, { ok: true, etag: '"x"', size: 5 }))
    const file = new File(['hello'], 'hello.txt', { type: 'text/plain' })
    await sdk.uploadObject({
      client,
      path: { bucket: 'media', key: 'docs/hello.txt' },
      body: file,
      headers: { 'Content-Type': file.type },
      throwOnError: true,
    })
    const request = requests[0]
    expect(request.method).toBe('PUT')
    expect(new URL(request.url).pathname).toBe('/api/buckets/media/upload/docs/hello.txt')
    expect(request.headers.get('Content-Type')).toBe('text/plain')
    expect(await request.text()).toBe('hello')
  })

  test('turns error payloads into ApiError', async () => {
    const { client, onUnauthorized } = setup(() => json(409, { error: 'Bucket not empty' }))
    const promise = sdk.deleteBucket({ client, path: { bucket: 'media' }, throwOnError: true })
    await expect(promise).rejects.toMatchObject({ name: 'ApiError', status: 409, message: 'Bucket not empty' })
    expect(onUnauthorized).not.toHaveBeenCalled()
  })

  test('reports 401 outside of the auth endpoints', async () => {
    const { client, onUnauthorized } = setup(() => json(401, { error: 'Unauthorized' }))
    await expect(sdk.listBuckets({ client, throwOnError: true })).rejects.toBeInstanceOf(ApiError)
    expect(onUnauthorized).toHaveBeenCalledTimes(1)

    await expect(sdk.checkAuth({ client, throwOnError: true })).rejects.toMatchObject({ status: 401 })
    expect(onUnauthorized).toHaveBeenCalledTimes(1)
  })
})
