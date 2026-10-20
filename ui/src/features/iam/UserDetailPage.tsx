import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useNavigate, useParams } from 'react-router'
import { ApiError } from '@/api/client'
import { iamKeys } from '@/api/queryKeys'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Callout } from '@/components/ui/callout'
import { ConfirmDialog } from '@/components/ui/confirm-dialog'
import { PageHeader } from '@/components/ui/page-header'
import { Switch } from '@/components/ui/switch'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { formatDate } from '@/lib/format'
import { toast } from '@/lib/toast'
import {
  attachUserPolicy,
  createAccessKey,
  deleteAccessKey,
  deleteIamUser,
  detachUserPolicy,
  getIamUser,
  listAccessKeys,
  listIamPolicies,
  putInlineUserPolicy,
  setAccessKeyStatus,
  setIamUserStatus,
} from './api'
import { CreateKeyDialog } from './CreateKeyDialog'

export function UserDetailPage() {
  const { name = '' } = useParams()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const userQuery = useQuery({ queryKey: iamKeys.user(name), queryFn: () => getIamUser(name), enabled: Boolean(name) })
  const keysQuery = useQuery({ queryKey: iamKeys.keys(name), queryFn: () => listAccessKeys(name), enabled: Boolean(name) })
  const policiesQuery = useQuery({ queryKey: iamKeys.policies(), queryFn: listIamPolicies })
  const [showKey, setShowKey] = useState(false)
  const [showGrant, setShowGrant] = useState(false)
  const [confirmDelete, setConfirmDelete] = useState(false)
  const [attachName, setAttachName] = useState('')

  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: iamKeys.user(name) })
    void queryClient.invalidateQueries({ queryKey: iamKeys.keys(name) })
    void queryClient.invalidateQueries({ queryKey: iamKeys.users() })
  }

  const status = useMutation({
    mutationFn: (enabled: boolean) => setIamUserStatus(name, enabled),
    onSuccess: refresh,
  })
  const remove = useMutation({
    mutationFn: () => deleteIamUser(name),
    onSuccess: () => {
      toast.success(`User "${name}" deleted`)
      navigate('/users')
      void queryClient.invalidateQueries({ queryKey: iamKeys.users() })
    },
  })
  const createKey = useMutation({
    mutationFn: createAccessKey.bind(null, name),
    onSuccess: refresh,
  })
  const keyStatus = useMutation({
    mutationFn: ({ id, next }: { id: string; next: 'Active' | 'Inactive' }) => setAccessKeyStatus(name, id, next),
    onSuccess: refresh,
  })
  const removeKey = useMutation({
    mutationFn: (id: string) => deleteAccessKey(name, id),
    onSuccess: refresh,
  })
  const grant = useMutation({
    mutationFn: ({ policy, documentJson }: { policy: string; documentJson: string }) =>
      putInlineUserPolicy(name, policy, documentJson),
    onSuccess: () => {
      toast.success('Scope granted to the user')
      refresh()
    },
  })
  const attach = useMutation({
    mutationFn: (policy: string) => attachUserPolicy(name, policy),
    onSuccess: () => {
      setAttachName('')
      refresh()
    },
  })
  const detach = useMutation({
    mutationFn: (policy: string) => detachUserPolicy(name, policy),
    onSuccess: refresh,
  })

  const user = userQuery.data
  const policies = policiesQuery.data?.policies ?? []
  const attached = new Set(user?.attachedPolicies ?? [])

  return (
    <div className="flex flex-col gap-8">
      <PageHeader
        title={name}
        description="Access keys and the policies that grant this user S3 access."
        actions={
          <Button variant="destructive" onClick={() => setConfirmDelete(true)}>
            Delete user
          </Button>
        }
      />

      {userQuery.isError ? (
        <Callout type="danger">{userQuery.error instanceof ApiError ? userQuery.error.message : 'Failed to load user'}</Callout>
      ) : null}

      {user ? (
        <div className="flex items-center justify-between rounded-lg border border-neutral-200 bg-white px-4 py-3 dark:border-white/[0.08] dark:bg-panel">
          <div>
            <div className="text-sm font-medium">Enabled</div>
            <p className="text-[13px] text-neutral-500 dark:text-fg-faint">
              Disabled users keep their keys, but those keys cannot sign in or call the API.
            </p>
          </div>
          <Switch checked={user.enabled} onCheckedChange={(enabled) => status.mutate(enabled)} aria-label="User enabled" />
        </div>
      ) : null}

      <section className="flex flex-col gap-3">
        <div className="flex items-center justify-between gap-3">
          <h2 className="text-base font-semibold">Policies</h2>
          <div className="flex items-center gap-2">
            <select
              className="input-cool"
              aria-label="Policy to attach"
              value={attachName}
              onChange={(event) => setAttachName(event.target.value)}
            >
              <option value="">Attach a policy</option>
              {policies
                .filter((policy) => !attached.has(policy.name))
                .map((policy) => (
                  <option key={policy.name} value={policy.name}>
                    {policy.name}
                  </option>
                ))}
            </select>
            <Button variant="outline" disabled={!attachName || attach.isPending} onClick={() => attach.mutate(attachName)}>
              Attach
            </Button>
            <Button variant="outline" onClick={() => setShowGrant(true)}>
              Grant scope to user
            </Button>
          </div>
        </div>
        {user && user.attachedPolicies.length === 0 && user.inlinePolicies.length === 0 ? (
          <Callout type="info">
            This user has no policies, so a new key cannot access data. Use Grant scope to user to add access.
            Creating a key only limits that key.
          </Callout>
        ) : null}
        <div className="flex flex-wrap gap-2">
          {user?.attachedPolicies.map((policy) => (
            <span key={policy} className="inline-flex items-center gap-2 rounded-md border border-neutral-200 px-2 py-1 text-xs dark:border-white/[0.08]">
              {policy}
              <button type="button" className="text-neutral-500 hover:text-black dark:hover:text-fg" onClick={() => detach.mutate(policy)}>
                Remove
              </button>
            </span>
          ))}
          {user?.inlinePolicies.map((policy) => (
            <span key={policy.name} className="rounded-md border border-dashed border-neutral-300 px-2 py-1 text-xs dark:border-white/20">
              inline: {policy.name}
            </span>
          ))}
        </div>
      </section>

      <section className="flex flex-col gap-3">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-semibold">Access keys</h2>
          <Button variant="highlighted" onClick={() => setShowKey(true)}>
            Create access key
          </Button>
        </div>
        {(keysQuery.data?.keys.length ?? 0) === 0 ? (
          <p className="text-sm text-neutral-500 dark:text-fg-faint">No access keys.</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Access key</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="w-40"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {keysQuery.data?.keys.map((key) => (
                <TableRow key={key.accessKeyId}>
                  <TableCell className="font-mono text-xs">{key.accessKeyId}</TableCell>
                  <TableCell>
                    <Badge variant={key.status === 'Active' ? 'success' : 'warning'} label={key.status} />
                  </TableCell>
                  <TableCell>{formatDate(key.createdAt)}</TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-2">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() =>
                          keyStatus.mutate({ id: key.accessKeyId, next: key.status === 'Active' ? 'Inactive' : 'Active' })
                        }
                      >
                        {key.status === 'Active' ? 'Deactivate' : 'Activate'}
                      </Button>
                      <Button variant="destructive" size="sm" onClick={() => removeKey.mutate(key.accessKeyId)}>
                        Delete
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </section>

      {showKey ? (
        <CreateKeyDialog
          title="Create access key"
          description="This scope limits only this key. It does not grant the user anything, and the key cannot do more than the user's policies already allow."
          submitLabel="Create key"
          saving={createKey.isPending}
          onClose={() => setShowKey(false)}
          onCreate={async (input) => {
            const created = await createKey.mutateAsync({
              buckets: input.buckets,
              prefix: input.prefix,
              access: input.access,
              keyOnly: true,
            })
            toast.success('Access key created')
            return { accessKeyId: created.accessKeyId, secretAccessKey: created.secretAccessKey }
          }}
        />
      ) : null}

      {showGrant ? (
        <CreateKeyDialog
          title="Grant scope to user"
          description="This adds an inline policy on the user. Every key can use it, except a key whose own policy is tighter. This does not create an access key."
          submitLabel="Grant scope"
          saving={grant.isPending}
          onClose={() => setShowGrant(false)}
          onCreate={async (input) => {
            const label = input.buckets[0] ? input.buckets[0] : 'all'
            const policyName = `grant-${label}-${input.access}`.replace(/[^A-Za-z0-9+=,.@_-]/g, '').slice(0, 64)
            await grant.mutateAsync({ policy: policyName, documentJson: input.documentJson })
            setShowGrant(false)
          }}
        />
      ) : null}

      {confirmDelete ? (
        <ConfirmDialog
          open
          title={`Delete ${name}?`}
          description="This deletes the user and every access key. It cannot be undone."
          confirmLabel="Delete user"
          confirmVariant="destructive"
          loading={remove.isPending}
          onClose={() => setConfirmDelete(false)}
          onConfirm={() => remove.mutate()}
        />
      ) : null}
    </div>
  )
}
