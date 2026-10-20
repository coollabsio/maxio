import { expect, test } from 'bun:test'
import { ApiError } from '@/api/client'
import { shouldRetryQuery } from './queryClient'

test('401 and 403 are not retried', () => {
  expect(shouldRetryQuery(0, new ApiError('Access Denied', 403))).toBe(false)
  expect(shouldRetryQuery(0, new ApiError('unauthorized', 401))).toBe(false)
  expect(shouldRetryQuery(0, new ApiError('unavailable', 503))).toBe(true)
  expect(shouldRetryQuery(1, new ApiError('unavailable', 503))).toBe(false)
})
