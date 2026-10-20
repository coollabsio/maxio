import { apiClient } from '@/api/client'
import * as sdk from '@/api/generated/sdk.gen'
import type {
  CreateKeyBody,
  PolicyUpdateBody,
  PolicyWriteBody,
  PreviewBody,
  ServiceKeyBody,
} from '@/api/generated/types.gen'

export async function listIamUsers() {
  const { data } = await sdk.listIamUsers({ client: apiClient, throwOnError: true })
  return data
}

export async function createIamUser(name: string) {
  const { data } = await sdk.createIamUser({ client: apiClient, body: { name }, throwOnError: true })
  return data
}

export async function getIamUser(name: string) {
  const { data } = await sdk.getIamUser({ client: apiClient, path: { name }, throwOnError: true })
  return data
}

export async function deleteIamUser(name: string) {
  const { data } = await sdk.deleteIamUser({ client: apiClient, path: { name }, throwOnError: true })
  return data
}

export async function setIamUserStatus(name: string, enabled: boolean) {
  const { data } = await sdk.setIamUserStatus({
    client: apiClient,
    path: { name },
    body: { enabled },
    throwOnError: true,
  })
  return data
}

export async function listAccessKeys(name: string) {
  const { data } = await sdk.listAccessKeys({ client: apiClient, path: { name }, throwOnError: true })
  return data
}

export async function createAccessKey(name: string, body: CreateKeyBody) {
  const { data } = await sdk.createAccessKey({ client: apiClient, path: { name }, body, throwOnError: true })
  return data
}

export async function setAccessKeyStatus(name: string, id: string, status: 'Active' | 'Inactive') {
  const { data } = await sdk.setAccessKeyStatus({
    client: apiClient,
    path: { name, id },
    body: { status },
    throwOnError: true,
  })
  return data
}

export async function deleteAccessKey(name: string, id: string) {
  const { data } = await sdk.deleteAccessKey({ client: apiClient, path: { name, id }, throwOnError: true })
  return data
}

export async function listServiceKeys() {
  const { data } = await sdk.listServiceKeys({ client: apiClient, throwOnError: true })
  return data
}

export async function createServiceKey(body: ServiceKeyBody) {
  const { data } = await sdk.createServiceKey({ client: apiClient, body, throwOnError: true })
  return data
}

export async function setServiceKeyStatus(id: string, status: 'Active' | 'Inactive') {
  const { data } = await sdk.setServiceKeyStatus({ client: apiClient, path: { id }, body: { status }, throwOnError: true })
  return data
}

export async function deleteServiceKey(id: string) {
  const { data } = await sdk.deleteServiceKey({ client: apiClient, path: { id }, throwOnError: true })
  return data
}

export async function listIamPolicies() {
  const { data } = await sdk.listIamPolicies({ client: apiClient, throwOnError: true })
  return data
}

export async function getIamPolicy(name: string) {
  const { data } = await sdk.getIamPolicy({ client: apiClient, path: { name }, throwOnError: true })
  return data
}

export async function createIamPolicy(body: PolicyWriteBody) {
  const { data } = await sdk.createIamPolicy({ client: apiClient, body, throwOnError: true })
  return data
}

export async function updateIamPolicy(name: string, body: PolicyUpdateBody) {
  const { data } = await sdk.updateIamPolicy({ client: apiClient, path: { name }, body, throwOnError: true })
  return data
}

export async function deleteIamPolicy(name: string) {
  const { data } = await sdk.deleteIamPolicy({ client: apiClient, path: { name }, throwOnError: true })
  return data
}

export async function putInlineUserPolicy(name: string, policy: string, documentJson: string) {
  const { data } = await sdk.putInlineUserPolicy({
    client: apiClient,
    path: { name, policy },
    body: { documentJson },
    throwOnError: true,
  })
  return data
}

export async function attachUserPolicy(name: string, policy: string) {
  const { data } = await sdk.attachUserPolicy({ client: apiClient, path: { name }, body: { name: policy }, throwOnError: true })
  return data
}

export async function detachUserPolicy(name: string, policy: string) {
  const { data } = await sdk.detachUserPolicy({ client: apiClient, path: { name, policy }, throwOnError: true })
  return data
}

export async function previewIamPolicy(body: PreviewBody) {
  const { data } = await sdk.previewIamPolicy({ client: apiClient, body, throwOnError: true })
  return data
}

export async function validateIamPolicy(documentJson: string) {
  const { data } = await sdk.validateIamPolicy({ client: apiClient, body: { documentJson }, throwOnError: true })
  return data
}

/** Client-side check before the server validates. Returns an error message, or null. */
export function policyJsonError(text: string): string | null {
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    return 'Policy must be valid JSON'
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return 'Policy must be a JSON object'
  const statement = (parsed as { Statement?: unknown }).Statement
  if (!statement || (typeof statement !== 'object' && !Array.isArray(statement))) {
    return 'Policy needs a Statement object or array'
  }
  const statements = Array.isArray(statement) ? statement : [statement]
  if (statements.length === 0) return 'Policy needs at least one statement'
  for (const item of statements) {
    if (!item || typeof item !== 'object') return 'Each statement must be an object'
    const effect = (item as { Effect?: unknown }).Effect
    if (effect !== 'Allow' && effect !== 'Deny') return 'Each statement Effect must be Allow or Deny'
  }
  return null
}
