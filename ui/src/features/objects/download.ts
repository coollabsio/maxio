import { ApiError } from '@/api/client'
import { displayName, downloadUrl, versionDownloadUrl } from '@/lib/paths'

/** Download an object without leaving the console. Errors stay in the page. */
export async function downloadObjectFile(bucket: string, key: string, versionId?: string) {
  const url = versionId ? versionDownloadUrl(bucket, key, versionId) : downloadUrl(bucket, key)
  const response = await fetch(url, { credentials: 'same-origin' })
  if (!response.ok) {
    let message = `Download failed (${response.status})`
    const text = await response.text()
    try {
      const body = JSON.parse(text) as { error?: unknown }
      if (typeof body.error === 'string' && body.error) message = body.error
    } catch {
      if (text.trim()) message = text.trim().slice(0, 200)
    }
    throw new ApiError(message, response.status)
  }
  const blob = await response.blob()
  const objectUrl = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = objectUrl
  anchor.download = displayName(key)
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  URL.revokeObjectURL(objectUrl)
}
