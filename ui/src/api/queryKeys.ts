export const iamKeys = {
  all: ['iam'] as const,
  users: () => [...iamKeys.all, 'users'] as const,
  user: (name: string) => [...iamKeys.all, 'user', name] as const,
  keys: (name: string) => [...iamKeys.all, 'keys', name] as const,
  serviceKeys: () => [...iamKeys.all, 'service-keys'] as const,
  policies: () => [...iamKeys.all, 'policies'] as const,
  policy: (name: string) => [...iamKeys.all, 'policy', name] as const,
}

export const authKeys = {
  all: ['auth'] as const,
  check: () => [...authKeys.all, 'check'] as const,
}

export const bucketKeys = {
  all: ['buckets'] as const,
  list: () => [...bucketKeys.all, 'list'] as const,
  detail: (bucket: string) => [...bucketKeys.all, 'detail', bucket] as const,
}

export const objectKeys = {
  all: ['objects'] as const,
  list: (bucket: string, prefix: string) => [...objectKeys.all, 'list', bucket, prefix] as const,
  info: (bucket: string, key: string) => [...objectKeys.all, 'info', bucket, key] as const,
}

export const versionKeys = {
  all: ['versions'] as const,
  list: (bucket: string, key: string) => [...versionKeys.all, 'list', bucket, key] as const,
}

export const settingsKeys = {
  all: ['settings'] as const,
  versioning: (bucket: string) => [...settingsKeys.all, 'versioning', bucket] as const,
  encryption: (bucket: string) => [...settingsKeys.all, 'encryption', bucket] as const,
  publicAccess: (bucket: string) => [...settingsKeys.all, 'public', bucket] as const,
  tags: (bucket: string) => [...settingsKeys.all, 'tags', bucket] as const,
  policy: (bucket: string) => [...settingsKeys.all, 'policy', bucket] as const,
  lifecycle: (bucket: string) => [...settingsKeys.all, 'lifecycle', bucket] as const,
}
