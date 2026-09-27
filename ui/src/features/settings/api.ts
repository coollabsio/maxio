import { apiClient } from '@/api/client'
import * as sdk from '@/api/generated/sdk.gen'

export async function getVersioning(bucket: string) {
  const { data } = await sdk.getVersioning({ client: apiClient, path: { bucket }, throwOnError: true })
  return data
}

export async function setVersioning(bucket: string, enabled: boolean) {
  const { data } = await sdk.setVersioning({ client: apiClient, path: { bucket }, body: { enabled }, throwOnError: true })
  return data
}

export async function getEncryption(bucket: string) {
  const { data } = await sdk.getEncryption({ client: apiClient, path: { bucket }, throwOnError: true })
  return data
}

export async function setEncryption(bucket: string, enabled: boolean) {
  const { data } = await sdk.setEncryption({ client: apiClient, path: { bucket }, body: { enabled }, throwOnError: true })
  return data
}

export async function getPublicAccess(bucket: string) {
  const { data } = await sdk.getPublicAccess({ client: apiClient, path: { bucket }, throwOnError: true })
  return data
}

export async function setPublicAccess(bucket: string, read: boolean, list: boolean) {
  const { data } = await sdk.setPublicAccess({
    client: apiClient,
    path: { bucket },
    body: { read, list },
    throwOnError: true,
  })
  return data
}
