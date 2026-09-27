import { apiClient } from '@/api/client'
import * as sdk from '@/api/generated/sdk.gen'

export async function listObjects(bucket: string, prefix: string) {
  const { data } = await sdk.listObjects({
    client: apiClient,
    path: { bucket },
    query: { prefix, delimiter: '/' },
    throwOnError: true,
  })
  return data
}

/** Streams the raw file as the request body, with the file's own content type. */
export async function uploadObject(bucket: string, key: string, file: File) {
  const { data } = await sdk.uploadObject({
    client: apiClient,
    path: { bucket, key },
    body: file,
    headers: { 'Content-Type': file.type || 'application/octet-stream' },
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
