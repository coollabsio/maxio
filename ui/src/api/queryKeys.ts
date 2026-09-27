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
}
