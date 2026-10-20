/** A key policy of `*` does not narrow the user. The console must not call that "Key policy: *". */
export function unrestrictedKeyPolicy(summary: string): boolean {
  const resources = summary.replace(/^Key policy:\s*/, '')
  return resources.split(',').every((part) => {
    const value = part.trim()
    return value === '*' || value === 'arn:aws:s3:::*'
  })
}

function sanitize(value: string): string {
  return value.replace(/[^A-Za-z0-9+=,.@_-]/g, '')
}

/** Inline policy name for a console grant, including the folder prefix. */
export function grantPolicyName(buckets: string[], prefix: string, access: string, taken: Iterable<string>): string {
  const bucket = sanitize(buckets[0] ?? '') || 'all'
  const folder = sanitize(prefix.trim().replace(/^\/+|\/+$/g, '').replaceAll('/', '-'))
  const level = sanitize(access) || 'read'
  const base = ['grant', bucket, folder, level].filter(Boolean).join('-').slice(0, 64) || 'grant'
  const used = new Set(taken)
  if (!used.has(base)) return base
  for (let n = 2; n < 100; n++) {
    const suffix = `-${n}`
    const name = `${base.slice(0, Math.max(1, 64 - suffix.length))}${suffix}`
    if (!used.has(name)) return name
  }
  return base
}

/** What the folder field becomes in the resource ARN. */
export function folderScopeHint(buckets: string[], prefix: string): string {
  const trimmed = prefix.trim().replace(/^\/+/, '')
  const folder = trimmed.replace(/\/+$/, '')
  const directory = folder ? `${folder}/` : ''
  const names = buckets.length > 0 ? buckets : ['<bucket>']
  if (!directory) {
    const arns = names.map((bucket) => `arn:aws:s3:::${bucket}/*`).join(', ')
    return `Empty means every object in the selected buckets. Resource: ${arns}`
  }
  const arns = names.map((bucket) => `arn:aws:s3:::${bucket}/${directory}*`).join(', ')
  return `Folder prefix. Matches objects under ${directory} only, not ${folder}X. Resource: ${arns}`
}
