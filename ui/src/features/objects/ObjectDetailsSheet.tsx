import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Check, Copy, LoaderCircle } from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { ApiError } from '@/api/client'
import { objectKeys } from '@/api/queryKeys'
import type { TagEntry } from '@/api/generated/types.gen'
import { Callout } from '@/components/ui/callout'
import { Sheet } from '@/components/ui/sheet'
import { TagSetForm } from '@/features/tags/TagEditor'
import { OBJECT_TAGS_MAX } from '@/features/tags/validation'
import { formatDate, formatSize } from '@/lib/format'
import { displayName } from '@/lib/paths'
import { toast } from '@/lib/toast'
import { getObjectInfo, setObjectTags } from './api'
import { storageFormatLabel } from './storageFormat'

interface ObjectDetailsSheetProps {
  bucket: string
  objectKey: string | null
  onClose: () => void
}

/** Right-hand drawer with every stored attribute of one object and its tag editor. */
export function ObjectDetailsSheet({ bucket, objectKey, onClose }: ObjectDetailsSheetProps) {
  return (
    <Sheet
      open={objectKey !== null}
      title={objectKey ? displayName(objectKey) : ''}
      description={objectKey ? `${bucket}/${objectKey}` : undefined}
      onClose={onClose}
      closeLabel="Close object details"
    >
      {objectKey ? <ObjectDetails bucket={bucket} objectKey={objectKey} /> : null}
    </Sheet>
  )
}

function ObjectDetails({ bucket, objectKey }: { bucket: string; objectKey: string }) {
  const queryClient = useQueryClient()
  const infoQuery = useQuery({
    queryKey: objectKeys.info(bucket, objectKey),
    queryFn: () => getObjectInfo(bucket, objectKey),
  })

  const tagsMutation = useMutation({
    mutationFn: (tags: TagEntry[]) => setObjectTags(bucket, objectKey, tags),
    onSuccess: () => {
      toast.success('Tags saved')
      void queryClient.invalidateQueries({ queryKey: objectKeys.info(bucket, objectKey) })
    },
    onError: (err) => {
      console.error('setObjectTags failed:', err)
      toast.error(err instanceof ApiError ? err.message : 'Failed to save tags')
    },
  })

  if (infoQuery.isPending) {
    return (
      <div className="flex items-center gap-2 text-sm text-neutral-500 dark:text-fg-faint">
        <LoaderCircle className="size-4 animate-spin" /> Loading details...
      </div>
    )
  }
  if (infoQuery.isError) {
    return (
      <Callout type="danger">
        {infoQuery.error instanceof ApiError ? infoQuery.error.message : 'Failed to load object details'}
      </Callout>
    )
  }

  const info = infoQuery.data
  const headers: [string, string | null][] = [
    ['Cache-Control', info.cacheControl],
    ['Content-Disposition', info.contentDisposition],
    ['Content-Encoding', info.contentEncoding],
    ['Content-Language', info.contentLanguage],
    ['Expires', info.expires],
  ]
  const presentHeaders = headers.filter((entry): entry is [string, string] => !!entry[1])
  const metadata = Object.entries(info.userMetadata)

  return (
    <div className="flex flex-col gap-6">
      <DetailSection title="Object">
        <DetailRow label="Key" value={<span className="break-all">{info.key}</span>} />
        <DetailRow label="Size" value={`${formatSize(info.size)} (${info.size.toLocaleString()} bytes)`} />
        <DetailRow label="Content type" value={info.contentType} />
        <DetailRow label="Last modified" value={formatDate(info.lastModified)} />
        <DetailRow label="ETag" value={<CopyValue value={info.etag} label="ETag" />} />
        {info.versionId ? (
          <DetailRow label="Version ID" value={<CopyValue value={info.versionId} label="version ID" />} />
        ) : null}
        <DetailRow label="Storage format" value={storageFormatLabel(info)} />
        {info.partCount ? <DetailRow label="Parts" value={String(info.partCount)} /> : null}
      </DetailSection>

      <DetailSection title="Integrity and encryption">
        <DetailRow
          label="Checksum"
          value={
            info.checksum ? (
              <span className="flex flex-col gap-0.5">
                <span className="text-xs font-medium text-neutral-500 dark:text-fg-faint">{info.checksum.algorithm}</span>
                {info.checksum.value ? <CopyValue value={info.checksum.value} label="checksum" /> : null}
              </span>
            ) : (
              <Muted>None</Muted>
            )
          }
        />
        <DetailRow
          label="Encryption"
          value={
            info.encryption ? (
              <span className="flex flex-col gap-0.5">
                <span>{info.encryption.mode}</span>
                {info.encryption.keyId ? (
                  <span className="font-mono text-xs text-neutral-500 dark:text-fg-faint">key {info.encryption.keyId}</span>
                ) : null}
              </span>
            ) : (
              <Muted>Not encrypted</Muted>
            )
          }
        />
      </DetailSection>

      {presentHeaders.length > 0 ? (
        <DetailSection title="HTTP headers">
          {presentHeaders.map(([name, value]) => (
            <DetailRow key={name} label={name} value={<span className="break-all">{value}</span>} />
          ))}
        </DetailSection>
      ) : null}

      <DetailSection title="User metadata">
        {metadata.length === 0 ? (
          <div className="px-3 py-2.5 text-[13px] text-neutral-500 dark:text-fg-faint">No user metadata</div>
        ) : (
          metadata.map(([name, value]) => (
            <DetailRow
              key={name}
              label={<span className="font-mono text-xs">{name}</span>}
              value={<span className="break-all">{value}</span>}
            />
          ))
        )}
      </DetailSection>

      <section className="flex flex-col gap-2">
        <h3 className="text-[13px] font-medium text-neutral-600 dark:text-fg-dim">Tags</h3>
        <TagSetForm
          key={JSON.stringify(info.tags)}
          initial={info.tags}
          max={OBJECT_TAGS_MAX}
          saving={tagsMutation.isPending}
          onSave={(tags) => tagsMutation.mutate(tags)}
          label="Object tag"
        />
      </section>
    </div>
  )
}

function DetailSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="flex flex-col gap-2">
      <h3 className="text-[13px] font-medium text-neutral-600 dark:text-fg-dim">{title}</h3>
      <dl className="divide-y divide-neutral-200 rounded-lg border border-neutral-200 bg-white dark:divide-white/[0.06] dark:border-white/[0.06] dark:bg-surface">
        {children}
      </dl>
    </section>
  )
}

function DetailRow({ label, value }: { label: ReactNode; value: ReactNode }) {
  return (
    <div className="grid grid-cols-[6.5rem_minmax(0,1fr)] gap-3 sm:grid-cols-[9rem_minmax(0,1fr)] px-3 py-2.5 text-[13px]">
      <dt className="text-neutral-500 dark:text-fg-faint">{label}</dt>
      <dd className="min-w-0 text-black dark:text-fg">{value}</dd>
    </div>
  )
}

function Muted({ children }: { children: ReactNode }) {
  return <span className="text-neutral-500 dark:text-fg-faint">{children}</span>
}

/** Monospace value with a copy-to-clipboard button. */
function CopyValue({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false)

  async function copy() {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch (err) {
      console.error('clipboard write failed:', err)
      toast.error('Could not copy to clipboard')
    }
  }

  return (
    <span className="flex items-start gap-1">
      <span className="min-w-0 break-all font-mono text-xs leading-5">{value}</span>
      <button
        type="button"
        className="icon-button -my-1 size-6"
        title={`Copy ${label}`}
        aria-label={`Copy ${label}`}
        onClick={() => void copy()}
      >
        {copied ? <Check className="size-3.5 text-success" /> : <Copy className="size-3.5" />}
      </button>
    </span>
  )
}
