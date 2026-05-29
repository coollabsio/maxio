import { apiClient } from '@/api/client'
import * as sdk from '@/api/generated/sdk.gen'
import { guessContentType } from '@/lib/mime'

export async function listObjects(bucket: string, prefix: string) {
  const { data } = await sdk.listObjects({
    client: apiClient,
    path: { bucket },
    query: { prefix, delimiter: '/' },
    throwOnError: true,
  })
  return data
}

/**
 * Streams the raw file as the request body. The content type is the browser's, falling back to a guess from the
 * file name (browsers leave `file.type` empty for source files, dotfiles and many config formats).
 */
export async function uploadObject(bucket: string, key: string, file: File) {
  const { data } = await sdk.uploadObject({
    client: apiClient,
    path: { bucket, key },
    body: file,
    headers: { 'Content-Type': file.type || guessContentType(file.name) || 'application/octet-stream' },
    throwOnError: true,
  })
  return data
}

export async function deleteObject(bucket: string, key: string) {
  const { data } = await sdk.deleteObject({ client: apiClient, path: { bucket, key }, throwOnError: true })
  return data
}

export async function createFolder(bucket: string, name: string) {
  const { data } = await sdk.createFolder({ client: apiClient, path: { bucket }, body: { name }, throwOnError: true })
  return data
}

export async function presignObject(bucket: string, key: string, expires: number) {
  const { data } = await sdk.presignObject({
    client: apiClient,
    path: { bucket, key },
    query: { expires },
    throwOnError: true,
  })
  return data
}
