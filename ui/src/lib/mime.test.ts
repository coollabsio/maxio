import { expect, test } from 'bun:test'
import { guessContentType } from './mime'

test('guessContentType uses the mime table for common extensions', () => {
  expect(guessContentType('photo.PNG')).toBe('image/png')
  expect(guessContentType('report.pdf')).toBe('application/pdf')
  expect(guessContentType('notes.md')).toBe('text/markdown')
})

test('guessContentType forces source and script files to a text type', () => {
  expect(guessContentType('app.ts')).toBe('text/plain')
  expect(guessContentType('main.rs')).toBe('text/x-rust')
  expect(guessContentType('run.sh')).toBe('application/x-sh')
  expect(guessContentType('config.jsonc')).toBe('application/json')
})

test('guessContentType matches extensionless config files by full name', () => {
  expect(guessContentType('Dockerfile')).toBe('text/plain')
  expect(guessContentType('.gitignore')).toBe('text/plain')
  expect(guessContentType('Makefile')).toBe('text/plain')
})

test('guessContentType is undefined for unknown extensions', () => {
  expect(guessContentType('blob.unknownext')).toBeUndefined()
  expect(guessContentType('noextension')).toBeUndefined()
})
