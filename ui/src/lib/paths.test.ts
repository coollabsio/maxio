import { describe, expect, test } from 'bun:test'
import {
  bucketPath,
  bucketSettingsPath,
  buildBreadcrumbs,
  displayName,
  downloadUrl,
  encodeObjectKey,
  normalizePrefix,
  parentPrefix,
  versionDownloadUrl,
} from './paths'

describe('encodeObjectKey', () => {
  test('encodes each segment but keeps slashes', () => {
    expect(encodeObjectKey('photos/my vacation/a#1?.jpg')).toBe('photos/my%20vacation/a%231%3F.jpg')
  })

  test('keeps trailing slash of folder markers', () => {
    expect(encodeObjectKey('folder/')).toBe('folder/')
  })
})

describe('displayName', () => {
  test('returns last segment of a key', () => {
    expect(displayName('a/b/c.txt')).toBe('c.txt')
    expect(displayName('top.txt')).toBe('top.txt')
  })

  test('drops the trailing slash of a prefix', () => {
    expect(displayName('a/b/')).toBe('b')
  })
})

describe('parentPrefix', () => {
  test('walks up one folder', () => {
    expect(parentPrefix('a/b/')).toBe('a/')
    expect(parentPrefix('a/')).toBe('')
  })

  test('returns null at the bucket root', () => {
    expect(parentPrefix('')).toBeNull()
  })
})

test('normalizePrefix adds a trailing slash', () => {
  expect(normalizePrefix(null)).toBe('')
  expect(normalizePrefix('a/b')).toBe('a/b/')
  expect(normalizePrefix('a/b/')).toBe('a/b/')
})

test('buildBreadcrumbs lists the bucket then every folder', () => {
  expect(buildBreadcrumbs('media', 'photos/2024/')).toEqual([
    { label: 'media', prefix: '' },
    { label: 'photos', prefix: 'photos/' },
    { label: '2024', prefix: 'photos/2024/' },
  ])
  expect(buildBreadcrumbs('media', '')).toEqual([{ label: 'media', prefix: '' }])
})

test('app and download paths', () => {
  expect(bucketPath('media')).toBe('/buckets/media')
  expect(bucketPath('media', 'a b/')).toBe('/buckets/media?prefix=a+b%2F')
  expect(bucketSettingsPath('media')).toBe('/buckets/media/settings')
  expect(downloadUrl('media', 'a b/c.txt')).toBe('/api/buckets/media/download/a%20b/c.txt')
  expect(versionDownloadUrl('media', 'a/c.txt', 'v/1')).toBe('/api/buckets/media/versions/v%2F1/download/a/c.txt')
})
