import { apiClient } from '@/api/client'
import * as sdk from '@/api/generated/sdk.gen'

export async function listVersions(bucket: string, key: string) {
  const { data } = await sdk.listVersions({ client: apiClient, path: { bucket }, query: { key }, throwOnError: true })
  return data
}

export async function deleteVersion(bucket: string, key: string, versionId: string) {
  const { data } = await sdk.deleteVersion({
    client: apiClient,
    path: { bucket, versionId, key },
    throwOnError: true,
  })
  return data
}
