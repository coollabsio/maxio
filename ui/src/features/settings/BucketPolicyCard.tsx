import { useQuery } from '@tanstack/react-query'
import { ApiError } from '@/api/client'
import { settingsKeys } from '@/api/queryKeys'
import { Callout } from '@/components/ui/callout'
import { getBucketPolicy } from './api'

function prettyJson(text: string): string {
  try {
    return JSON.stringify(JSON.parse(text), null, 2)
  } catch {
    return text
  }
}

/** Read-only view of the bucket policy generated from the public access toggles. */
export function BucketPolicyCard({ bucket }: { bucket: string }) {
  const policyQuery = useQuery({ queryKey: settingsKeys.policy(bucket), queryFn: () => getBucketPolicy(bucket) })
  const policy = policyQuery.data?.policy

  return (
    <section className="settings-section">
      <div className="settings-section-header">
        <h2>Access policy</h2>
        <p>Read-only. The public read and public listing toggles above control this policy.</p>
      </div>
      <div className="settings-section-body p-4">
        {policyQuery.isPending ? (
          <p className="text-[13px] text-neutral-500 dark:text-fg-faint">Loading...</p>
        ) : policyQuery.isError ? (
          <Callout type="danger">
            {policyQuery.error instanceof ApiError ? policyQuery.error.message : 'Failed to load bucket policy'}
          </Callout>
        ) : policy ? (
          <pre className="max-h-80 overflow-auto rounded-md border border-neutral-200 bg-neutral-50 p-3 font-mono text-xs leading-5 text-black dark:border-white/[0.06] dark:bg-black/20 dark:text-fg-dim">
            {prettyJson(policy)}
          </pre>
        ) : (
          <p className="text-[13px] text-neutral-500 dark:text-fg-faint">
            No bucket policy. Only signed requests can access this bucket.
          </p>
        )}
      </div>
    </section>
  )
}
