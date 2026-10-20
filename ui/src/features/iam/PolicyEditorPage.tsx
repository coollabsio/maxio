import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useNavigate, useParams } from 'react-router'
import { ApiError } from '@/api/client'
import { iamKeys } from '@/api/queryKeys'
import { Button } from '@/components/ui/button'
import { Callout } from '@/components/ui/callout'
import { Input } from '@/components/ui/input'
import { PageHeader } from '@/components/ui/page-header'
import { toast } from '@/lib/toast'
import { createIamPolicy, deleteIamPolicy, getIamPolicy, policyJsonError, updateIamPolicy, validateIamPolicy } from './api'

const starter = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": ["arn:aws:s3:::example", "arn:aws:s3:::example/*"]
    }
  ]
}
`

export function PolicyEditorPage() {
  const params = useParams()
  const isNew = params.name === 'new' || !params.name
  const name = isNew ? '' : (params.name ?? '')
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const existing = useQuery({
    queryKey: iamKeys.policy(name),
    queryFn: () => getIamPolicy(name),
    enabled: !isNew,
  })

  return (
    <Editor
      key={existing.data?.updatedAt ?? 'new'}
      isNew={isNew}
      initialName={existing.data?.name ?? ''}
      initialDescription={existing.data?.description ?? ''}
      initialDocument={existing.data?.documentJson ?? starter}
      builtin={existing.data?.builtin ?? false}
      loading={existing.isPending && !isNew}
      error={existing.error}
      onSave={async (input) => {
        if (isNew) {
          const created = await createIamPolicy(input)
          toast.success(`Policy "${created.name}" created`)
          await queryClient.invalidateQueries({ queryKey: iamKeys.policies() })
          navigate(`/policies/${created.name}`)
          return
        }
        await updateIamPolicy(name, { description: input.description, documentJson: input.documentJson })
        toast.success(`Policy "${name}" saved`)
        await queryClient.invalidateQueries({ queryKey: iamKeys.policies() })
        await queryClient.invalidateQueries({ queryKey: iamKeys.policy(name) })
      }}
      onDelete={async () => {
        await deleteIamPolicy(name)
        toast.success(`Policy "${name}" deleted`)
        await queryClient.invalidateQueries({ queryKey: iamKeys.policies() })
        navigate('/policies')
      }}
    />
  )
}

function Editor({
  isNew,
  initialName,
  initialDescription,
  initialDocument,
  builtin,
  loading,
  error,
  onSave,
  onDelete,
}: {
  isNew: boolean
  initialName: string
  initialDescription: string
  initialDocument: string
  builtin: boolean
  loading: boolean
  error: unknown
  onSave: (input: { name: string; description: string; documentJson: string }) => Promise<void>
  onDelete: () => Promise<void>
}) {
  const [policyName, setPolicyName] = useState(initialName)
  const [description, setDescription] = useState(initialDescription)
  const [documentJson, setDocumentJson] = useState(initialDocument)
  const [message, setMessage] = useState('')
  const [messageType, setMessageType] = useState<'info' | 'danger'>('info')
  const save = useMutation({ mutationFn: onSave })
  const remove = useMutation({ mutationFn: onDelete })
  const localError = policyJsonError(documentJson)

  async function validate() {
    const problem = policyJsonError(documentJson)
    if (problem) {
      setMessageType('danger')
      setMessage(problem)
      return
    }
    try {
      const result = await validateIamPolicy(documentJson)
      setDocumentJson(result.documentJson)
      setMessageType('info')
      setMessage('Policy is valid.')
    } catch (err) {
      console.error('validate policy failed:', err)
      setMessageType('danger')
      setMessage(err instanceof ApiError ? err.message : 'Validation failed')
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title={isNew ? 'New policy' : policyName || 'Policy'}
        description={
          builtin
            ? 'Built-in policies are fixed. Attach them to a user, or copy the JSON into a custom policy.'
            : 'Effect, Action (including s3:Get*), and Resource ARNs such as arn:aws:s3:::bucket/prefix*. Explicit Deny wins.'
        }
        actions={
          builtin ? null : (
            <div className="flex gap-2">
              {isNew ? null : (
                <Button variant="destructive" disabled={remove.isPending} onClick={() => void remove.mutateAsync()}>
                  Delete
                </Button>
              )}
              <Button variant="outline" onClick={() => void validate()}>
                Validate
              </Button>
              <Button
                variant="highlighted"
                disabled={save.isPending || Boolean(localError) || (isNew && !policyName.trim())}
                onClick={() => {
                  setMessage('')
                  save.mutate(
                    { name: policyName.trim(), description, documentJson },
                    {
                      onError: (err) => {
                        setMessageType('danger')
                        setMessage(err instanceof ApiError ? err.message : 'Failed to save policy')
                      },
                    },
                  )
                }}
              >
                {save.isPending ? 'Saving...' : 'Save'}
              </Button>
            </div>
          )
        }
      />

      {loading ? <p className="text-sm text-muted-foreground">Loading...</p> : null}
      {error ? (
        <Callout type="danger">{error instanceof ApiError ? error.message : 'Failed to load policy'}</Callout>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-[16rem_1fr]">
        <label className="flex flex-col gap-1.5 text-[13px] font-medium text-neutral-600 dark:text-fg-dim">
          Name
          <Input value={policyName} disabled={!isNew} onChange={(event) => setPolicyName(event.target.value)} />
        </label>
        <label className="flex flex-col gap-1.5 text-[13px] font-medium text-neutral-600 dark:text-fg-dim">
          Description
          <Input value={description} disabled={builtin} onChange={(event) => setDescription(event.target.value)} />
        </label>
      </div>
      <label className="flex flex-col gap-1.5 text-[13px] font-medium text-neutral-600 dark:text-fg-dim">
        Policy JSON
        <textarea
          aria-label="Policy JSON"
          className="input-cool min-h-80 w-full resize-y px-3 py-2 font-mono text-xs"
          value={documentJson}
          readOnly={builtin}
          onChange={(event) => setDocumentJson(event.target.value)}
        />
      </label>
      {localError && !builtin ? <Callout type="danger">{localError}</Callout> : null}
      {message ? <Callout type={messageType}>{message}</Callout> : null}
    </div>
  )
}
