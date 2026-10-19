import type { LifecycleFilter, LifecycleRule, TagEntry } from '@/api/generated/types.gen'
import { formatVersionSize } from '@/lib/format'
import { cleanTags, validateTags } from '@/features/tags/validation'

export type ExpirationMode = 'none' | 'days' | 'date' | 'deleteMarkers'

/** Editable state of one lifecycle rule: every number is the raw input text. */
export interface LifecycleRuleForm {
  id: string
  enabled: boolean
  prefix: string
  tags: TagEntry[]
  sizeGreaterThan: string
  sizeLessThan: string
  expirationMode: ExpirationMode
  expirationDays: string
  /** `YYYY-MM-DD` (midnight UTC). */
  expirationDate: string
  noncurrentDays: string
  keepNewest: string
  abortDays: string
}

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`

const text = (n: number | null | undefined) => (n == null ? '' : String(n))

export function emptyRuleForm(): LifecycleRuleForm {
  return {
    id: '',
    enabled: true,
    prefix: '',
    tags: [],
    sizeGreaterThan: '',
    sizeLessThan: '',
    expirationMode: 'none',
    expirationDays: '',
    expirationDate: '',
    noncurrentDays: '',
    keepNewest: '',
    abortDays: '',
  }
}

export function ruleToForm(rule: LifecycleRule): LifecycleRuleForm {
  const exp = rule.expiration
  let expirationMode: ExpirationMode = 'none'
  if (exp?.days != null) expirationMode = 'days'
  else if (exp?.date) expirationMode = 'date'
  else if (exp?.expiredObjectDeleteMarker) expirationMode = 'deleteMarkers'
  return {
    id: rule.id ?? '',
    enabled: rule.status === 'Enabled',
    prefix: rule.filter?.prefix ?? '',
    tags: (rule.filter?.tags ?? []).map((t) => ({ key: t.key, value: t.value ?? '' })),
    sizeGreaterThan: text(rule.filter?.objectSizeGreaterThan),
    sizeLessThan: text(rule.filter?.objectSizeLessThan),
    expirationMode,
    expirationDays: text(exp?.days),
    expirationDate: exp?.date ? exp.date.slice(0, 10) : '',
    noncurrentDays: text(rule.noncurrentVersionExpiration?.noncurrentDays),
    keepNewest: text(rule.noncurrentVersionExpiration?.newerNoncurrentVersions),
    abortDays: text(rule.abortIncompleteMultipartUpload?.daysAfterInitiation),
  }
}

/** Parses a whole number ≥ `min`; `undefined` for an empty input, `null` when invalid. */
function parseWhole(input: string, min: number): number | null | undefined {
  const s = input.trim()
  if (s === '') return undefined
  if (!/^\d+$/.test(s)) return null
  const n = Number(s)
  return Number.isSafeInteger(n) && n >= min ? n : null
}

/** Builds the API rule from the form, or the first validation problem. */
export function formToRule(form: LifecycleRuleForm): { rule?: LifecycleRule; error?: string } {
  const id = form.id.trim()
  if (Array.from(id).length > 255) return { error: 'Rule ID must be at most 255 characters' }

  const filter: LifecycleFilter = {}
  if (form.prefix) filter.prefix = form.prefix
  const tags = cleanTags(form.tags)
  const tagError = validateTags(tags, 50)
  if (tagError) return { error: tagError }
  if (tags.length > 0) filter.tags = tags
  const gt = parseWhole(form.sizeGreaterThan, 0)
  const lt = parseWhole(form.sizeLessThan, 0)
  if (gt === null || lt === null) return { error: 'Sizes must be whole numbers of bytes' }
  if (gt !== undefined && lt !== undefined && gt >= lt) {
    return { error: 'Minimum size must be smaller than maximum size' }
  }
  if (gt !== undefined) filter.objectSizeGreaterThan = gt
  if (lt !== undefined) filter.objectSizeLessThan = lt

  const rule: LifecycleRule = { id, status: form.enabled ? 'Enabled' : 'Disabled', filter }

  if (form.expirationMode === 'days') {
    const days = parseWhole(form.expirationDays, 1)
    if (days == null) return { error: 'Expiration days must be a positive whole number' }
    rule.expiration = { days }
  } else if (form.expirationMode === 'date') {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(form.expirationDate)) return { error: 'Pick an expiration date' }
    rule.expiration = { date: form.expirationDate }
  } else if (form.expirationMode === 'deleteMarkers') {
    if (tags.length > 0) return { error: 'Delete marker cleanup cannot use a tag filter' }
    rule.expiration = { expiredObjectDeleteMarker: true }
  }

  const noncurrentDays = parseWhole(form.noncurrentDays, 1)
  const keepNewest = parseWhole(form.keepNewest, 1)
  if (noncurrentDays === null) return { error: 'Noncurrent days must be a positive whole number' }
  if (keepNewest === null || (keepNewest !== undefined && keepNewest > 100)) {
    return { error: 'Versions to keep must be between 1 and 100' }
  }
  if (keepNewest !== undefined && noncurrentDays === undefined) {
    return { error: 'Set the noncurrent days to keep newer versions' }
  }
  if (noncurrentDays !== undefined) {
    rule.noncurrentVersionExpiration = { noncurrentDays }
    if (keepNewest !== undefined) rule.noncurrentVersionExpiration.newerNoncurrentVersions = keepNewest
  }

  const abortDays = parseWhole(form.abortDays, 1)
  if (abortDays === null) return { error: 'Abort days must be a positive whole number' }
  if (abortDays !== undefined) {
    if (tags.length > 0) return { error: 'Incomplete uploads cannot be aborted by a tag filter' }
    rule.abortIncompleteMultipartUpload = { daysAfterInitiation: abortDays }
  }

  if (!rule.expiration && !rule.noncurrentVersionExpiration && !rule.abortIncompleteMultipartUpload) {
    return { error: 'Choose at least one action' }
  }
  return { rule }
}

/** One line per action, e.g. "Expire after 30 days". */
export function summarizeActions(rule: LifecycleRule): string[] {
  const out: string[] = []
  const exp = rule.expiration
  if (exp?.days != null) out.push(`Expire after ${plural(exp.days, 'day')}`)
  else if (exp?.date) out.push(`Expire on ${exp.date.slice(0, 10)}`)
  if (exp?.expiredObjectDeleteMarker) out.push('Remove expired delete markers')
  const nve = rule.noncurrentVersionExpiration
  if (nve) {
    const keep = nve.newerNoncurrentVersions != null ? ` (keep ${nve.newerNoncurrentVersions})` : ''
    out.push(
      nve.noncurrentDays != null
        ? `Delete noncurrent versions after ${plural(nve.noncurrentDays, 'day')}${keep}`
        : `Delete noncurrent versions${keep}`,
    )
  }
  const abort = rule.abortIncompleteMultipartUpload
  if (abort) out.push(`Abort incomplete uploads after ${plural(abort.daysAfterInitiation, 'day')}`)
  return out
}

/** Which objects the rule applies to, e.g. `Prefix "logs/" · Tag env=dev`. */
export function summarizeFilter(rule: LifecycleRule): string {
  const f = rule.filter ?? {}
  const parts: string[] = []
  if (f.prefix) parts.push(`Prefix "${f.prefix}"`)
  for (const tag of f.tags ?? []) parts.push(`Tag ${tag.key}=${tag.value ?? ''}`)
  if (f.objectSizeGreaterThan != null) parts.push(`Larger than ${formatVersionSize(f.objectSizeGreaterThan)}`)
  if (f.objectSizeLessThan != null) parts.push(`Smaller than ${formatVersionSize(f.objectSizeLessThan)}`)
  return parts.length > 0 ? parts.join(' · ') : 'Whole bucket'
}

/** The rule only has an effect on versioned buckets (noncurrent versions, delete markers). */
export function usesNoncurrentVersions(rule: LifecycleRule): boolean {
  return !!rule.noncurrentVersionExpiration || !!rule.expiration?.expiredObjectDeleteMarker
}
