import type { TagEntry } from '@/api/generated/types.gen'

/** S3 limits: 10 tags per object, 50 per bucket. */
export const OBJECT_TAGS_MAX = 10
export const BUCKET_TAGS_MAX = 50

const KEY_MAX = 128
const VALUE_MAX = 256

const length = (s: string) => Array.from(s).length

/** Removes untouched rows (blank key and value) the editor keeps for the next entry. */
export function cleanTags(tags: TagEntry[]): TagEntry[] {
  return tags.filter((tag) => tag.key !== '' || tag.value !== '')
}

/** First problem with a tag set (same rules as the server), or `null` when it is valid. */
export function validateTags(tags: TagEntry[], max: number, options: { rejectAwsPrefix?: boolean } = {}): string | null {
  if (tags.length > max) return `At most ${max} tags are allowed`
  const seen = new Set<string>()
  for (const { key, value } of tags) {
    if (length(key) < 1 || length(key) > KEY_MAX) return `Tag keys must be 1–${KEY_MAX} characters`
    if (length(value) > VALUE_MAX) return `Tag values must be at most ${VALUE_MAX} characters`
    if (options.rejectAwsPrefix && key.startsWith('aws:')) return 'Tag keys starting with "aws:" are reserved'
    if (seen.has(key)) return `Duplicate tag key "${key}"`
    seen.add(key)
  }
  return null
}

/** Same set of key/value pairs, in any order. */
export function tagsEqual(a: TagEntry[], b: TagEntry[]): boolean {
  if (a.length !== b.length) return false
  const map = new Map(a.map((tag) => [tag.key, tag.value]))
  return b.every((tag) => map.has(tag.key) && map.get(tag.key) === tag.value)
}
