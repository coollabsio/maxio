import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Plus, Users } from 'lucide-react'
import { useState } from 'react'
import { useNavigate } from 'react-router'
import { ApiError } from '@/api/client'
import { iamKeys } from '@/api/queryKeys'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Callout } from '@/components/ui/callout'
import { ConfirmDialog } from '@/components/ui/confirm-dialog'
import { Dialog } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { PageHeader } from '@/components/ui/page-header'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { formatDate } from '@/lib/format'
import { toast } from '@/lib/toast'
import { createIamUser, createServiceKey, deleteServiceKey, listIamUsers, listServiceKeys, setServiceKeyStatus } from './api'
import { CreateKeyDialog } from './CreateKeyDialog'

export function UsersPage() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const usersQuery = useQuery({ queryKey: iamKeys.users(), queryFn: listIamUsers })
  const serviceQuery = useQuery({ queryKey: iamKeys.serviceKeys(), queryFn: listServiceKeys })
  const [showUser, setShowUser] = useState(false)
  const [userName, setUserName] = useState('')
  const [userError, setUserError] = useState('')
  const [showService, setShowService] = useState(false)
  const [serviceKeyToDelete, setServiceKeyToDelete] = useState<string | null>(null)

  const createUser = useMutation({
    mutationFn: createIamUser,
    onSuccess: (user) => {
      toast.success(`User "${user.name}" created`)
      setShowUser(false)
      setUserName('')
      void queryClient.invalidateQueries({ queryKey: iamKeys.users() })
      navigate(`/users/${user.name}`)
    },
  })

  const createService = useMutation({
    mutationFn: createServiceKey,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: iamKeys.serviceKeys() })
    },
  })

  const serviceStatus = useMutation({
    mutationFn: ({ id, status }: { id: string; status: 'Active' | 'Inactive' }) => setServiceKeyStatus(id, status),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: iamKeys.serviceKeys() }),
  })

  const removeService = useMutation({
    mutationFn: deleteServiceKey,
    onSuccess: () => {
      toast.success('Service key deleted')
      void queryClient.invalidateQueries({ queryKey: iamKeys.serviceKeys() })
    },
  })

  const users = usersQuery.data?.users ?? []
  const serviceKeys = serviceQuery.data?.keys ?? []

  return (
    <div className="flex flex-col gap-8">
      <PageHeader
        title="Users"
        description="IAM users sign in with their own access keys. Root credentials stay the administrator."
        actions={
          <Button variant="highlighted" onClick={() => setShowUser(true)}>
            <Plus /> Create user
          </Button>
        }
      />

      {usersQuery.isError ? (
        <Callout type="danger">
          {usersQuery.error instanceof ApiError ? usersQuery.error.message : 'Failed to load users'}
        </Callout>
      ) : usersQuery.isPending ? (
        <p className="text-sm text-muted-foreground">Loading...</p>
      ) : users.length === 0 ? (
        <Callout type="info">
          <span className="inline-flex items-center gap-2">
            <Users className="size-4 opacity-70" />
            No IAM users yet. Root can still sign in and manage storage.
          </span>
        </Callout>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Keys</TableHead>
              <TableHead>Policies</TableHead>
              <TableHead>Created</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {users.map((user) => (
              <TableRow key={user.name} className="cursor-pointer" onClick={() => navigate(`/users/${user.name}`)}>
                <TableCell className="font-medium">{user.name}</TableCell>
                <TableCell>
                  <Badge variant={user.enabled ? 'success' : 'warning'} label={user.enabled ? 'Enabled' : 'Disabled'} />
                </TableCell>
                <TableCell>{user.keyCount}</TableCell>
                <TableCell>{user.attachedPolicies.length + user.inlinePolicies.length}</TableCell>
                <TableCell>{formatDate(user.createdAt)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}

      <div className="flex flex-col gap-4">
        <PageHeader
          title="Service keys"
          description="Standalone keys for applications. The scope you pick is the key's only policy."
          actions={
            <Button variant="outline" onClick={() => setShowService(true)}>
              <Plus /> Create service key
            </Button>
          }
        />
        {serviceQuery.isError ? (
          <Callout type="danger">
            {serviceQuery.error instanceof ApiError ? serviceQuery.error.message : 'Failed to load service keys'}
          </Callout>
        ) : serviceKeys.length === 0 ? (
          <p className="text-sm text-neutral-500 dark:text-fg-faint">No service keys.</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Access key</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="w-40"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {serviceKeys.map((key) => (
                <TableRow key={key.accessKeyId}>
                  <TableCell className="font-medium">{key.label}</TableCell>
                  <TableCell className="font-mono text-xs">{key.accessKeyId}</TableCell>
                  <TableCell>
                    <Badge variant={key.status === 'Active' ? 'success' : 'warning'} label={key.status} />
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-2">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() =>
                          void serviceStatus.mutateAsync({
                            id: key.accessKeyId,
                            status: key.status === 'Active' ? 'Inactive' : 'Active',
                          })
                        }
                      >
                        {key.status === 'Active' ? 'Deactivate' : 'Activate'}
                      </Button>
                      <Button variant="destructive" size="sm" onClick={() => setServiceKeyToDelete(key.accessKeyId)}>
                        Delete
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </div>

      {serviceKeyToDelete ? (
        <ConfirmDialog
          open
          title="Delete service key?"
          description={`This permanently deletes ${serviceKeyToDelete}. Anything using it will stop working.`}
          confirmLabel="Delete key"
          confirmVariant="destructive"
          loading={removeService.isPending}
          onClose={() => setServiceKeyToDelete(null)}
          onConfirm={() => {
            const id = serviceKeyToDelete
            removeService.mutate(id, { onSuccess: () => setServiceKeyToDelete(null) })
          }}
        />
      ) : null}

      {showUser ? (
        <Dialog
          open
          title="Create user"
          description="The user starts with no policies. Grant a scope on the user page so keys can read or write. Creating an access key only narrows that key."
          loading={createUser.isPending}
          onClose={() => {
            setShowUser(false)
            setUserError('')
          }}
          footer={
            <>
              <Button variant="ghost" disabled={createUser.isPending} onClick={() => setShowUser(false)}>
                Cancel
              </Button>
              <Button
                variant="highlighted"
                disabled={createUser.isPending || !userName.trim()}
                onClick={() => {
                  setUserError('')
                  createUser.mutate(userName.trim(), {
                    onError: (err) => setUserError(err instanceof ApiError ? err.message : 'Failed to create user'),
                  })
                }}
              >
                Create
              </Button>
            </>
          }
        >
          <div className="mt-4 flex flex-col gap-3">
            <label className="flex flex-col gap-1.5 text-[13px] font-medium text-neutral-600 dark:text-fg-dim">
              User name
              <Input value={userName} onChange={(event) => setUserName(event.target.value)} autoFocus />
            </label>
            {userError ? <Callout type="danger">{userError}</Callout> : null}
          </div>
        </Dialog>
      ) : null}

      {showService ? (
        <CreateKeyDialog
          title="Create service key"
          description="This policy is the only access the key has. It is not attached to a user."
          submitLabel="Create service key"
          saving={createService.isPending}
          requireName
          onClose={() => setShowService(false)}
          onCreate={async (input) => {
            const created = await createService.mutateAsync({
              name: input.name,
              buckets: input.buckets,
              prefix: input.prefix,
              access: input.access,
            })
            return { accessKeyId: created.accessKeyId, secretAccessKey: created.secretAccessKey }
          }}
        />
      ) : null}
    </div>
  )
}
