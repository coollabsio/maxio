import { apiClient } from '@/api/client'
import * as sdk from '@/api/generated/sdk.gen'
import type { LifecycleRule } from '@/api/generated/types.gen'

export async function getBucketLifecycle(bucket: string) {
  const { data } = await sdk.getBucketLifecycle({ client: apiClient, path: { bucket }, throwOnError: true })
  return data
}

/** Replaces the whole rule set (an empty list removes the configuration); returns the stored rules. */
export async function setBucketLifecycle(bucket: string, rules: LifecycleRule[]) {
  const { data } = await sdk.setBucketLifecycle({ client: apiClient, path: { bucket }, body: { rules }, throwOnError: true })
  return data
}
