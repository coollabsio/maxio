import { apiClient } from '@/api/client'
import * as sdk from '@/api/generated/sdk.gen'
import type { LoginRequest } from '@/api/generated/types.gen'

export async function checkAuth() {
  const { data } = await sdk.checkAuth({ client: apiClient, throwOnError: true })
  return data
}

export async function login(input: LoginRequest) {
  const { data } = await sdk.login({ client: apiClient, body: input, throwOnError: true })
  return data
}

export async function logout() {
  const { data } = await sdk.logout({ client: apiClient, throwOnError: true })
  return data
}
