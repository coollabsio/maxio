import { apiClient } from '@/api/client'
import * as sdk from '@/api/generated/sdk.gen'

export type { BucketSummary as Bucket } from '@/api/generated/types.gen'

export async function listBuckets() {
  const { data } = await sdk.listBuckets({ client: apiClient, throwOnError: true })
  return data
}

export async function createBucket(name: string) {
  const { data } = await sdk.createBucket({ client: apiClient, body: { name }, throwOnError: true })
  return data
}

export async function deleteBucket(bucket: string) {
  const { data } = await sdk.deleteBucket({ client: apiClient, path: { bucket }, throwOnError: true })
  return data
}
