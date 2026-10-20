import { expect, test } from 'bun:test'
import { policyJsonError } from './api'

test('accepts an allow statement', () => {
  expect(
    policyJsonError('{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}'),
  ).toBeNull()
})

test('rejects invalid JSON and a missing effect', () => {
  expect(policyJsonError('{')).toBe('Policy must be valid JSON')
  expect(policyJsonError('{"Statement":{"Action":"s3:*"}}')).toBe('Each statement Effect must be Allow or Deny')
})
