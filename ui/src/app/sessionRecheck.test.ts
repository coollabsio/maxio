import { expect, test } from 'bun:test'
import { shouldRecheckSession } from './sessionRecheck'

test('bfcache restore, visible tab, and window focus recheck the session', () => {
  expect(shouldRecheckSession({ type: 'pageshow', persisted: true })).toBe(true)
  expect(shouldRecheckSession({ type: 'pageshow', persisted: false })).toBe(false)
  expect(shouldRecheckSession({ type: 'visibilitychange', visibilityState: 'visible' })).toBe(true)
  expect(shouldRecheckSession({ type: 'visibilitychange', visibilityState: 'hidden' })).toBe(false)
  expect(shouldRecheckSession({ type: 'focus' })).toBe(true)
  expect(shouldRecheckSession({ type: 'click' })).toBe(false)
})
