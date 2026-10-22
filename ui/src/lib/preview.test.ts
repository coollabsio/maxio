import { expect, test } from 'bun:test'
import { BINARY_PREVIEW_CAP, TEXT_PREVIEW_CAP, isPreviewable, previewKind } from './preview'

test('previewKind classifies images and PDFs', () => {
  expect(previewKind('image/png')).toBe('image')
  expect(previewKind('image/svg+xml')).toBe('image')
  expect(previewKind('application/pdf')).toBe('pdf')
})

test('previewKind treats text and text-like application types as text', () => {
  expect(previewKind('text/plain; charset=utf-8')).toBe('text')
  expect(previewKind('text/csv')).toBe('text')
  expect(previewKind('application/json')).toBe('text')
  expect(previewKind('application/x-sh')).toBe('text')
  expect(previewKind('application/ld+json')).toBe('text')
  expect(previewKind('application/atom+xml')).toBe('text')
})

test('previewKind never renders HTML inline', () => {
  expect(previewKind('text/html')).toBe('unsupported')
  expect(previewKind('TEXT/HTML; charset=utf-8')).toBe('unsupported')
})

test('previewKind rejects unknown, binary and empty types', () => {
  expect(previewKind('')).toBe('unsupported')
  expect(previewKind('application/octet-stream')).toBe('unsupported')
  expect(previewKind('application/zip')).toBe('unsupported')
  expect(isPreviewable('application/zip')).toBe(false)
  expect(isPreviewable('text/markdown')).toBe(true)
})

test('preview size caps', () => {
  expect(TEXT_PREVIEW_CAP).toBe(1024 * 1024)
  expect(BINARY_PREVIEW_CAP).toBe(10 * 1024 * 1024)
})
