import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ApiError } from '@/api/client'
import { bucketKeys, settingsKeys } from '@/api/queryKeys'
import type { TagEntry } from '@/api/generated/types.gen'
import { Callout } from '@/components/ui/callout'
import { TagSetForm } from '@/features/tags/TagEditor'
import { BUCKET_TAGS_MAX } from '@/features/tags/validation'
import { toast } from '@/lib/toast'
import { getBucketTags, setBucketTags } from './api'

export function BucketTagsCard({ bucket }: { bucket: string }) {
  const queryClient = useQueryClient()
  const tagsQuery = useQuery({ queryKey: settingsKeys.tags(bucket), queryFn: () => getBucketTags(bucket) })

  const mutation = useMutation({
    mutationFn: (tags: TagEntry[]) => setBucketTags(bucket, tags),
    onSuccess: () => {
      toast.success('Bucket tags saved')
      void queryClient.invalidateQueries({ queryKey: settingsKeys.tags(bucket) })
      void queryClient.invalidateQueries({ queryKey: bucketKeys.list() })
    },
    onError: (err) => {
      console.error('setBucketTags failed:', err)
      toast.error(err instanceof ApiError ? err.message : 'Failed to save bucket tags')
    },
  })

  return (
    <section className="settings-section">
      <div className="settings-section-header">
        <h2>Tags</h2>
        <p>Key/value labels for this bucket (up to {BUCKET_TAGS_MAX}). Keys starting with "aws:" are reserved.</p>
      </div>
      <div className="settings-section-body p-4">
        {tagsQuery.isPending ? (
          <p className="text-[13px] text-neutral-500 dark:text-fg-faint">Loading...</p>
        ) : tagsQuery.isError ? (
          <Callout type="danger">
            {tagsQuery.error instanceof ApiError ? tagsQuery.error.message : 'Failed to load bucket tags'}
          </Callout>
        ) : (
          <TagSetForm
            key={JSON.stringify(tagsQuery.data.tags)}
            initial={tagsQuery.data.tags}
            max={BUCKET_TAGS_MAX}
            rejectAwsPrefix
            saving={mutation.isPending}
            onSave={(tags) => mutation.mutate(tags)}
            label="Bucket tag"
          />
        )}
      </div>
    </section>
  )
}
