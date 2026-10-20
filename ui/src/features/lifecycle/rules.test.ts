import { describe, expect, test } from 'bun:test'
import type { LifecycleRule } from '@/api/generated/types.gen'
import { emptyRuleForm, formToRule, ruleToForm, summarizeActions, summarizeFilter, usesNoncurrentVersions } from './rules'

const full: LifecycleRule = {
  id: 'logs',
  status: 'Enabled',
  filter: {
    prefix: 'logs/',
    tags: [{ key: 'env', value: 'dev' }],
    objectSizeGreaterThan: 1024,
    objectSizeLessThan: 1048576,
  },
  expiration: { days: 30 },
  noncurrentVersionExpiration: { noncurrentDays: 7, newerNoncurrentVersions: 2 },
}

describe('summarizeActions', () => {
  test('describes every action', () => {
    expect(summarizeActions(full)).toEqual([
      'Expire after 30 days',
      'Delete noncurrent versions after 7 days (keep 2)',
    ])
    expect(summarizeActions({ status: 'Enabled', abortIncompleteMultipartUpload: { daysAfterInitiation: 3 } })).toEqual(
      ['Abort incomplete uploads after 3 days'],
    )
  })

  test('singular days, dates and delete markers', () => {
    expect(
      summarizeActions({
        status: 'Enabled',
        expiration: { days: 1 },
        noncurrentVersionExpiration: { noncurrentDays: 1 },
        abortIncompleteMultipartUpload: { daysAfterInitiation: 1 },
      }),
    ).toEqual([
      'Expire after 1 day',
      'Delete noncurrent versions after 1 day',
      'Abort incomplete uploads after 1 day',
    ])
    expect(summarizeActions({ status: 'Enabled', expiration: { date: '2030-01-01T00:00:00.000Z' } })).toEqual([
      'Expire on 2030-01-01',
    ])
    expect(summarizeActions({ status: 'Enabled', expiration: { expiredObjectDeleteMarker: true } })).toEqual([
      'Remove expired delete markers',
    ])
    expect(
      summarizeActions({ status: 'Enabled', noncurrentVersionExpiration: { newerNoncurrentVersions: 3 } }),
    ).toEqual(['Delete noncurrent versions (keep 3)'])
    expect(summarizeActions({ status: 'Enabled', expiration: null })).toEqual([])
  })
})

describe('summarizeFilter', () => {
  test('whole bucket when nothing is set', () => {
    expect(summarizeFilter({ status: 'Enabled' })).toBe('Whole bucket')
    expect(summarizeFilter({ status: 'Enabled', filter: { prefix: '' } })).toBe('Whole bucket')
  })

  test('joins prefix, tags and sizes', () => {
    expect(summarizeFilter(full)).toBe('Prefix "logs/" · Tag env=dev · Larger than 1 KiB · Smaller than 1 MiB')
  })
})

describe('usesNoncurrentVersions', () => {
  test('detects noncurrent and delete-marker actions', () => {
    expect(usesNoncurrentVersions(full)).toBe(true)
    expect(usesNoncurrentVersions({ status: 'Enabled', expiration: { expiredObjectDeleteMarker: true } })).toBe(true)
    expect(usesNoncurrentVersions({ status: 'Enabled', expiration: { days: 3 } })).toBe(false)
  })
})

describe('ruleToForm / formToRule', () => {
  test('round-trips a full rule', () => {
    expect(formToRule(ruleToForm(full))).toEqual({ rule: full })
  })

  test('round-trips a date expiration (date-only input)', () => {
    const rule: LifecycleRule = {
      id: 'd',
      status: 'Disabled',
      filter: {},
      expiration: { date: '2030-01-01T00:00:00.000Z' },
    }
    const form = ruleToForm(rule)
    expect(form.expirationMode).toBe('date')
    expect(form.expirationDate).toBe('2030-01-01')
    expect(formToRule(form)).toEqual({ rule: { ...rule, expiration: { date: '2030-01-01' } } })
  })

  test('delete-marker cleanup', () => {
    const form = { ...emptyRuleForm(), expirationMode: 'deleteMarkers' as const }
    expect(formToRule(form)).toEqual({
      rule: { id: '', status: 'Enabled', filter: {}, expiration: { expiredObjectDeleteMarker: true } },
    })
  })

  test('omits empty optional parts and trims inputs', () => {
    const form = { ...emptyRuleForm(), id: '  r1 ', expirationMode: 'days' as const, expirationDays: ' 5 ' }
    expect(formToRule(form)).toEqual({
      rule: { id: 'r1', status: 'Enabled', filter: {}, expiration: { days: 5 } },
    })
  })

  test('drops blank tag rows', () => {
    const form = {
      ...emptyRuleForm(),
      expirationMode: 'days' as const,
      expirationDays: '2',
      tags: [
        { key: '', value: '' },
        { key: 'a', value: 'b' },
      ],
    }
    expect(formToRule(form).rule?.filter).toEqual({ tags: [{ key: 'a', value: 'b' }] })
  })

  test('validation errors', () => {
    const base = emptyRuleForm()
    expect(formToRule(base).error).toBe('Choose at least one action')
    expect(formToRule({ ...base, expirationMode: 'days', expirationDays: '0' }).error).toBe(
      'Expiration days must be a positive whole number',
    )
    expect(formToRule({ ...base, expirationMode: 'days', expirationDays: '1.5' }).error).toBe(
      'Expiration days must be a positive whole number',
    )
    expect(formToRule({ ...base, expirationMode: 'date', expirationDate: '' }).error).toBe('Pick an expiration date')
    expect(formToRule({ ...base, keepNewest: '2' }).error).toBe('Set the noncurrent days to keep newer versions')
    expect(formToRule({ ...base, noncurrentDays: '3', keepNewest: '101' }).error).toBe(
      'Versions to keep must be between 1 and 100',
    )
    expect(formToRule({ ...base, abortDays: '1', sizeGreaterThan: '10', sizeLessThan: '10' }).error).toBe(
      'Minimum size must be smaller than maximum size',
    )
    expect(formToRule({ ...base, abortDays: '1', sizeGreaterThan: '-1' }).error).toBe(
      'Sizes must be whole numbers of bytes',
    )
    expect(
      formToRule({ ...base, abortDays: '1', tags: [{ key: 'a', value: '' }] }).error,
    ).toBe('Incomplete uploads cannot be aborted by a tag filter')
    expect(
      formToRule({ ...base, expirationMode: 'deleteMarkers', tags: [{ key: 'a', value: '' }] }).error,
    ).toBe('Delete marker cleanup cannot use a tag filter')
    expect(formToRule({ ...base, abortDays: '1', id: 'x'.repeat(256) }).error).toBe(
      'Rule ID must be at most 255 characters',
    )
  })
})
