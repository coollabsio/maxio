import type { ObjectInfo } from '@/api/generated/types.gen'

/** On-disk layout label. "Plain" would read as unencrypted, which SSE-S3 is not. */
export function storageFormatLabel(info: Pick<ObjectInfo, 'storageFormat' | 'encryption' | 'inlinePayload'>): string {
  if (info.storageFormat === 'chunked') return 'Chunked'
  if (info.storageFormat === 'erasure') return 'Erasure coded'
  if (info.inlinePayload && info.encryption) return 'Single encrypted file (key/.maxio.object)'
  if (info.inlinePayload) return 'Single file (key/.maxio.object)'
  if (info.encryption) return 'Single file (encrypted)'
  return 'Single file'
}
