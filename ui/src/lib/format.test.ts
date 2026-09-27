import { expect, test } from 'bun:test'
import { formatDate, formatSize, formatVersionSize, truncateId } from './format'

test('formatSize', () => {
  expect(formatSize(0)).toBe('0 B')
  expect(formatSize(1023)).toBe('1023 B')
  expect(formatSize(1536)).toBe('1.5 KB')
  expect(formatSize(2 * 1024 * 1024)).toBe('2.0 MB')
  expect(formatSize(3 * 1024 * 1024 * 1024)).toBe('3.0 GB')
})

test('formatVersionSize', () => {
  expect(formatVersionSize(0)).toBe('0 B')
  expect(formatVersionSize(1024)).toBe('1 KB')
  expect(formatVersionSize(1.5 * 1024 * 1024)).toBe('1.5 MB')
})

test('formatDate falls back to the input', () => {
  expect(formatDate('not a date')).toBe('not a date')
  expect(formatDate('2024-01-02T03:04:05Z')).toBe(new Date('2024-01-02T03:04:05Z').toLocaleString())
})

test('truncateId', () => {
  expect(truncateId('short')).toBe('short')
  expect(truncateId('abcdefghijklmnopqrstuvwxyz')).toBe('abcdefghijklmnop...')
})
