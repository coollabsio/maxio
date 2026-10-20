import { useQuery } from '@tanstack/react-query'
import { Check, Copy } from 'lucide-react'
import { useState } from 'react'
import { ApiError } from '@/api/client'
import { Button } from '@/components/ui/button'
import { Callout } from '@/components/ui/callout'
import { Dialog } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { previewIamPolicy } from './api'
import { folderScopeHint } from './grantName'

export type ScopeAccess = 'read' | 'write' | 'readwrite' | 'admin'

const accessOptions: { value: ScopeAccess; label: string }[] = [
  { value: 'read', label: 'Read' },
  { value: 'write', label: 'Write' },
  { value: 'readwrite', label: 'Read and write' },
  { value: 'admin', label: 'Admin' },
]

export function CreateKeyDialog({
  title,
  description,
  submitLabel,
  saving,
  requireName = false,
  onClose,
  onCreate,
}: {
  title: string
  description: string
  submitLabel: string
  saving: boolean
  onClose: () => void
  requireName?: boolean
  onCreate: (input: {
    name: string
    buckets: string[]
    prefix: string
    access: ScopeAccess
    documentJson: string
  }) => Promise<{ accessKeyId: string; secretAccessKey: string } | void>
}) {
  const [name, setName] = useState('')
  const [buckets, setBuckets] = useState('')
  const [prefix, setPrefix] = useState('')
  const [access, setAccess] = useState<ScopeAccess>('read')
  const [error, setError] = useState('')
  const [secret, setSecret] = useState<{ accessKeyId: string; secretAccessKey: string } | null>(null)
  const [copied, setCopied] = useState(false)

  const bucketList = buckets
    .split(',')
    .map((name) => name.trim())
    .filter(Boolean)

  const preview = useQuery({
    queryKey: ['iam', 'preview', bucketList.join(','), prefix, access],
    queryFn: () => previewIamPolicy({ buckets: bucketList, prefix, access }),
  })

  async function submit() {
    setError('')
    try {
      if (requireName && !name.trim()) {
        setError('Name is required')
        return
      }
      const documentJson = preview.data?.documentJson
      if (!documentJson) {
        setError('The scope policy is not ready yet')
        return
      }
      const created = await onCreate({
        name: name.trim(),
        buckets: bucketList,
        prefix: prefix.trim(),
        access,
        documentJson,
      })
      if (created) setSecret(created)
    } catch (err) {
      console.error('create access key failed:', err)
      setError(err instanceof ApiError ? err.message : 'Failed to create the access key')
    }
  }

  async function copySecret() {
    if (!secret) return
    await navigator.clipboard.writeText(secret.secretAccessKey)
    setCopied(true)
  }

  if (secret) {
    return (
      <Dialog
        open
        title="Access key created"
        description="Copy the secret now. MaxIO stores it encrypted and will not show it again."
        onClose={onClose}
        footer={
          <Button variant="highlighted" onClick={onClose}>
            Done
          </Button>
        }
      >
        <div className="mt-4 flex flex-col gap-3">
          <Callout type="warning">This secret is shown once. Store it in a password manager.</Callout>
          <div className="flex flex-col gap-1.5">
            <span className="text-[13px] font-medium text-neutral-600 dark:text-fg-dim">Access key ID</span>
            <code className="rounded-md bg-neutral-100 px-2 py-1.5 font-mono text-xs dark:bg-white/[0.06]">
              {secret.accessKeyId}
            </code>
          </div>
          <div className="flex flex-col gap-1.5">
            <span className="text-[13px] font-medium text-neutral-600 dark:text-fg-dim">Secret access key</span>
            <div className="flex items-start gap-2">
              <code className="min-w-0 flex-1 break-all rounded-md bg-neutral-100 px-2 py-1.5 font-mono text-xs dark:bg-white/[0.06]">
                {secret.secretAccessKey}
              </code>
              <Button type="button" variant="outline" onClick={() => void copySecret()} aria-label="Copy secret">
                {copied ? <Check /> : <Copy />}
                {copied ? 'Copied' : 'Copy'}
              </Button>
            </div>
          </div>
        </div>
      </Dialog>
    )
  }

  return (
    <Dialog
      open
      title={title}
      description={description}
      loading={saving}
      onClose={onClose}
      footer={
        <>
          <Button variant="ghost" disabled={saving} onClick={onClose}>
            Cancel
          </Button>
          <Button variant="highlighted" disabled={saving || preview.isError || !preview.data} onClick={() => void submit()}>
            {saving ? 'Saving...' : submitLabel}
          </Button>
        </>
      }
    >
      <div className="mt-4 flex flex-col gap-3">
        {requireName ? (
          <label className="flex flex-col gap-1.5 text-[13px] font-medium text-neutral-600 dark:text-fg-dim">
            Name
            <Input value={name} onChange={(event) => setName(event.target.value)} placeholder="backup" />
          </label>
        ) : null}
        <label className="flex flex-col gap-1.5 text-[13px] font-medium text-neutral-600 dark:text-fg-dim">
          Buckets
          <Input
            value={buckets}
            onChange={(event) => setBuckets(event.target.value)}
            placeholder="All buckets, or pics, logs"
          />
        </label>
        <label className="flex flex-col gap-1.5 text-[13px] font-medium text-neutral-600 dark:text-fg-dim">
          Folder (prefix)
          <Input
            value={prefix}
            onChange={(event) => setPrefix(event.target.value)}
            placeholder="reports"
            aria-label="Folder (prefix)"
            aria-describedby="folder-prefix-hint"
          />
          <span id="folder-prefix-hint" className="text-xs font-normal text-neutral-500 dark:text-fg-faint">
            {folderScopeHint(bucketList, prefix)}
          </span>
        </label>
        <label className="flex flex-col gap-1.5 text-[13px] font-medium text-neutral-600 dark:text-fg-dim">
          Access
          <select
            className="input-cool"
            value={access}
            onChange={(event) => setAccess(event.target.value as ScopeAccess)}
            aria-label="Access"
          >
            {accessOptions.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
        <div className="flex flex-col gap-1.5">
          <span className="text-[13px] font-medium text-neutral-600 dark:text-fg-dim">Generated policy</span>
          <textarea
            readOnly
            aria-label="Generated policy"
            className="input-cool min-h-36 w-full resize-y px-3 py-2 font-mono text-xs"
            value={preview.data?.documentJson ?? (preview.isPending ? 'Generating policy...' : '')}
          />
        </div>
        {preview.isError ? (
          <Callout type="danger">
            {preview.error instanceof ApiError ? preview.error.message : 'Could not generate a policy'}
          </Callout>
        ) : null}
        {error ? <Callout type="danger">{error}</Callout> : null}
      </div>
    </Dialog>
  )
}
