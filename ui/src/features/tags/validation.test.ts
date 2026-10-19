import { describe, expect, test } from 'bun:test'
import { BUCKET_TAGS_MAX, OBJECT_TAGS_MAX, cleanTags, tagsEqual, validateTags } from './validation'

describe('cleanTags', () => {
  test('drops rows where both key and value are blank', () => {
    expect(
      cleanTags([
        { key: 'a', value: '1' },
        { key: '', value: '' },
        { key: '', value: 'x' },
      ]),
    ).toEqual([
      { key: 'a', value: '1' },
      { key: '', value: 'x' },
    ])
  })
})

describe('validateTags', () => {
  test('accepts a valid set, including empty values', () => {
    expect(validateTags([{ key: 'env', value: '' }], OBJECT_TAGS_MAX)).toBeNull()
    expect(validateTags([], OBJECT_TAGS_MAX)).toBeNull()
  })

  test('enforces the maximum count', () => {
    const tags = Array.from({ length: 11 }, (_, i) => ({ key: `k${i}`, value: 'v' }))
    expect(validateTags(tags, OBJECT_TAGS_MAX)).toBe('At most 10 tags are allowed')
    expect(validateTags(tags, BUCKET_TAGS_MAX)).toBeNull()
  })

  test('checks key and value length (in characters)', () => {
    expect(validateTags([{ key: '', value: 'v' }], 10)).toBe('Tag keys must be 1–128 characters')
    expect(validateTags([{ key: 'k'.repeat(129), value: '' }], 10)).toBe('Tag keys must be 1–128 characters')
    expect(validateTags([{ key: 'é'.repeat(128), value: '' }], 10)).toBeNull()
    expect(validateTags([{ key: 'k', value: 'v'.repeat(257) }], 10)).toBe('Tag values must be at most 256 characters')
  })

  test('rejects duplicate keys', () => {
    expect(
      validateTags(
        [
          { key: 'a', value: '1' },
          { key: 'a', value: '2' },
        ],
        10,
      ),
    ).toBe('Duplicate tag key "a"')
  })

  test('optionally rejects reserved aws: keys', () => {
    expect(validateTags([{ key: 'aws:x', value: '' }], 10)).toBeNull()
    expect(validateTags([{ key: 'aws:x', value: '' }], 10, { rejectAwsPrefix: true })).toBe(
      'Tag keys starting with "aws:" are reserved',
    )
  })
})

describe('tagsEqual', () => {
  test('ignores order', () => {
    expect(
      tagsEqual(
        [
          { key: 'a', value: '1' },
          { key: 'b', value: '2' },
        ],
        [
          { key: 'b', value: '2' },
          { key: 'a', value: '1' },
        ],
      ),
    ).toBe(true)
    expect(tagsEqual([{ key: 'a', value: '1' }], [{ key: 'a', value: '2' }])).toBe(false)
    expect(tagsEqual([{ key: 'a', value: '1' }], [])).toBe(false)
  })
})
