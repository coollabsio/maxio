import { expect, test } from 'bun:test'
import { storageFormatLabel } from './storageFormat'

test('storage format does not call an encrypted object a plain file', () => {
  expect(storageFormatLabel({ storageFormat: 'plain', encryption: null, inlinePayload: false })).toBe('Single file')
  expect(
    storageFormatLabel({
      storageFormat: 'plain',
      encryption: { mode: 'SSE-S3', keyId: 'abc' },
      inlinePayload: false,
    }),
  ).toBe('Single file (encrypted)')
  expect(
    storageFormatLabel({
      storageFormat: 'plain',
      encryption: { mode: 'SSE-S3', keyId: 'abc' },
      inlinePayload: true,
    }),
  ).toBe('Single encrypted file (key/.maxio.object)')
})
