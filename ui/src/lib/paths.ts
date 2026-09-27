export interface Breadcrumb {
  label: string
  prefix: string
}

/** Encodes each path segment of an object key but keeps the `/` separators (for `{*key}` wildcard routes). */
export function encodeObjectKey(key: string): string {
  return key.split('/').map(encodeURIComponent).join('/')
}

/** Last path segment of a key or prefix: `a/b/c.txt` → `c.txt`, `a/b/` → `b`. */
export function displayName(fullPath: string): string {
  const trimmed = fullPath.endsWith('/') ? fullPath.slice(0, -1) : fullPath
  const lastSlash = trimmed.lastIndexOf('/')
  return lastSlash >= 0 ? trimmed.slice(lastSlash + 1) : trimmed
}

/** Prefix one folder up: `a/b/` → `a/`, `a/` → `''`. Returns `null` at the bucket root. */
export function parentPrefix(prefix: string): string | null {
  if (!prefix) return null
  const trimmed = prefix.slice(0, -1)
  const lastSlash = trimmed.lastIndexOf('/')
  return lastSlash >= 0 ? trimmed.slice(0, lastSlash + 1) : ''
}

/** Normalizes a prefix from the URL so it is either empty or ends with `/`. */
export function normalizePrefix(prefix: string | null | undefined): string {
  if (!prefix) return ''
  return prefix.endsWith('/') ? prefix : `${prefix}/`
}

/** Bucket root followed by one crumb per folder in `prefix`. */
export function buildBreadcrumbs(bucket: string, prefix: string): Breadcrumb[] {
  const crumbs: Breadcrumb[] = [{ label: bucket, prefix: '' }]
  let acc = ''
  for (const part of prefix.split('/').filter(Boolean)) {
    acc += `${part}/`
    crumbs.push({ label: part, prefix: acc })
  }
  return crumbs
}

/** In-app location of a bucket's object browser (optionally inside a folder). */
export function bucketPath(bucket: string, prefix = ''): string {
  const base = `/buckets/${encodeURIComponent(bucket)}`
  return prefix ? `${base}?${new URLSearchParams({ prefix })}` : base
}

export function bucketSettingsPath(bucket: string): string {
  return `/buckets/${encodeURIComponent(bucket)}/settings`
}

/** Same-origin URL that downloads the current version of an object. */
export function downloadUrl(bucket: string, key: string): string {
  return `/api/buckets/${encodeURIComponent(bucket)}/download/${encodeObjectKey(key)}`
}

/** Same-origin URL that downloads a specific version of an object. */
export function versionDownloadUrl(bucket: string, key: string, versionId: string): string {
  return `/api/buckets/${encodeURIComponent(bucket)}/versions/${encodeURIComponent(versionId)}/download/${encodeObjectKey(key)}`
}
