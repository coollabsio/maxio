export type PreviewKind = 'image' | 'pdf' | 'text' | 'unsupported'

export const TEXT_PREVIEW_CAP = 1024 * 1024 // 1 MiB
export const BINARY_PREVIEW_CAP = 10 * 1024 * 1024 // 10 MiB

// application/* subtypes that are really text (some clients label scripts and
// config files with these rather than a text/* type).
const TEXT_APP_TYPES = new Set([
  'application/json',
  'application/xml',
  'application/javascript',
  'application/x-javascript',
  'application/x-sh',
  'application/x-shellscript',
  'application/yaml',
  'application/x-yaml',
  'application/toml',
  'application/x-toml',
])

function normalize(contentType: string): string {
  return contentType.split(';')[0].trim().toLowerCase()
}

export function previewKind(contentType: string): PreviewKind {
  const ct = normalize(contentType)
  if (!ct) return 'unsupported'

  // SVG renders safely via <img> (no script execution in that context).
  if (ct.startsWith('image/')) return 'image'
  if (ct === 'application/pdf') return 'pdf'

  // text/* is previewable EXCEPT text/html, which we never render inline to
  // avoid stored-XSS in the console's same-origin session.
  if (ct === 'text/html') return 'unsupported'
  if (ct.startsWith('text/')) return 'text'

  if (TEXT_APP_TYPES.has(ct)) return 'text'
  if (ct.endsWith('+json') || ct.endsWith('+xml')) return 'text'

  return 'unsupported'
}

export function isPreviewable(contentType: string): boolean {
  return previewKind(contentType) !== 'unsupported'
}
