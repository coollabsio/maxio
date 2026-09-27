import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Database, Plus, Settings, Trash2 } from 'lucide-react'
import { useRef, useState, type MouseEvent } from 'react'
import { useNavigate } from 'react-router'
import { ApiError } from '@/api/client'
import { bucketKeys } from '@/api/queryKeys'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Callout } from '@/components/ui/callout'
import { ConfirmDialog } from '@/components/ui/confirm-dialog'
import { Dialog } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { formatDate } from '@/lib/format'
import { bucketPath, bucketSettingsPath } from '@/lib/paths'
import { toast } from '@/lib/toast'
import { createBucket, deleteBucket, listBuckets } from './api'

export function BucketListPage() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [newBucketName, setNewBucketName] = useState('')
  const [createError, setCreateError] = useState('')
  const [bucketToDelete, setBucketToDelete] = useState<string | null>(null)
  const createBucketInput = useRef<HTMLInputElement>(null)

  const bucketsQuery = useQuery({ queryKey: bucketKeys.list(), queryFn: listBuckets })
  const buckets = bucketsQuery.data?.buckets ?? []

  const createBucketMutation = useMutation({
    mutationFn: createBucket,
    onSuccess: (_data, name) => {
      toast.success(`Bucket "${name}" created`)
      setNewBucketName('')
      setShowCreate(false)
      void queryClient.invalidateQueries({ queryKey: bucketKeys.list() })
    },
  })

  const deleteBucketMutation = useMutation({
    mutationFn: deleteBucket,
    onSuccess: (_data, name) => {
      toast.success(`Bucket "${name}" deleted`)
      void queryClient.invalidateQueries({ queryKey: bucketKeys.list() })
    },
  })

  function closeCreate() {
    setShowCreate(false)
    setNewBucketName('')
    setCreateError('')
  }

  async function submitCreate() {
    const name = newBucketName.trim()
    if (!name) return
    try {
      await createBucketMutation.mutateAsync(name)
    } catch (err) {
      console.error('createBucket failed:', err)
      // Shown in the dialog: the server says why the name is rejected (length, characters, ...).
      setCreateError(err instanceof ApiError ? err.message : 'Failed to connect to server')
    }
  }

  async function confirmDeleteBucket() {
    if (!bucketToDelete) return
    try {
      await deleteBucketMutation.mutateAsync(bucketToDelete)
      setBucketToDelete(null)
    } catch (err) {
      console.error('deleteBucket failed:', err)
      toast.error(err instanceof ApiError ? err.message : 'Failed to connect to server')
    }
  }

  function stop(event: MouseEvent, action: () => void) {
    event.stopPropagation()
    action()
  }

  return (
    <>
      <div className="flex flex-col gap-4">
        {bucketsQuery.isError ? (
          <Callout type="danger">
            {bucketsQuery.error instanceof ApiError ? bucketsQuery.error.message : 'Failed to load buckets'}
          </Callout>
        ) : null}

        <div className="flex items-center gap-2">
          <Button variant="highlighted" className="h-8" onClick={() => setShowCreate(true)}>
            <Plus className="size-4 mr-1" /> Create Bucket
          </Button>
        </div>

        {bucketsQuery.isPending ? (
          <p className="text-sm text-muted-foreground">Loading...</p>
        ) : buckets.length === 0 && !bucketsQuery.isError ? (
          <Callout type="info">
            <span className="inline-flex items-center gap-2">
              <Database className="size-4 opacity-70" />
              No buckets yet — create your first bucket to get started.
            </span>
          </Callout>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Versioning</TableHead>
                <TableHead>Encryption</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="w-20"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {buckets.map((bucket) => (
                <TableRow key={bucket.name} className="cursor-pointer" onClick={() => navigate(bucketPath(bucket.name))}>
                  <TableCell className="font-medium">{bucket.name}</TableCell>
                  <TableCell>
                    {bucket.versioning ? (
                      <Badge variant="success" label="Enabled" />
                    ) : (
                      <span className="text-xs text-muted-foreground">Disabled</span>
                    )}
                  </TableCell>
                  <TableCell>
                    {bucket.encryption ? (
                      <span className="inline-flex items-center rounded-sm bg-green-500/10 px-1.5 py-0.5 text-[11px] font-medium text-green-500">
                        Enabled
                      </span>
                    ) : (
                      <span className="text-xs text-muted-foreground">Disabled</span>
                    )}
                  </TableCell>
                  <TableCell className="text-muted-foreground">{formatDate(bucket.createdAt)}</TableCell>
                  <TableCell className="w-20">
                    <div className="flex items-center gap-4">
                      <button
                        type="button"
                        className="text-muted-foreground hover:text-foreground transition-colors"
                        onClick={(event) => stop(event, () => navigate(bucketSettingsPath(bucket.name)))}
                        title="Bucket settings"
                        aria-label="Bucket settings"
                      >
                        <Settings className="size-4" />
                      </button>
                      <button
                        type="button"
                        className="text-muted-foreground hover:text-destructive transition-colors"
                        onClick={(event) => stop(event, () => setBucketToDelete(bucket.name))}
                        title="Delete bucket"
                        aria-label="Delete bucket"
                      >
                        <Trash2 className="size-4" />
                      </button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </div>

      <Dialog
        open={showCreate}
        title="Create bucket"
        description="Choose a unique bucket name for your objects."
        loading={createBucketMutation.isPending}
        onClose={closeCreate}
        initialFocus={createBucketInput}
        footer={
          <>
            <Button variant="default" disabled={createBucketMutation.isPending} onClick={closeCreate}>
              Cancel
            </Button>
            <Button
              type="submit"
              form="create-bucket-form"
              variant="highlighted"
              disabled={createBucketMutation.isPending || !newBucketName.trim()}
            >
              {createBucketMutation.isPending ? 'Creating…' : 'Create bucket'}
            </Button>
          </>
        }
      >
        <form
          id="create-bucket-form"
          onSubmit={(event) => {
            event.preventDefault()
            void submitCreate()
          }}
          className="flex flex-col gap-1.5"
        >
          <label htmlFor="bucket-name" className="text-sm font-medium text-black dark:text-white">
            Bucket name
          </label>
          <Input
            ref={createBucketInput}
            id="bucket-name"
            type="text"
            value={newBucketName}
            onChange={(event) => {
              setNewBucketName(event.target.value)
              setCreateError('')
            }}
            placeholder="bucket-name"
            className="bg-white dark:bg-base"
            disabled={createBucketMutation.isPending}
            aria-invalid={createError ? true : undefined}
            aria-describedby="bucket-name-hint"
          />
          {createError ? (
            <p role="alert" className="text-sm text-error">
              {createError}
            </p>
          ) : null}
          <p id="bucket-name-hint" className="text-xs text-muted-foreground">
            3-63 characters: lowercase letters, numbers, hyphens (-), and dots (.). Start and end with a letter or
            number.
          </p>
        </form>
      </Dialog>

      <ConfirmDialog
        open={bucketToDelete !== null}
        title="Delete bucket?"
        description={`This will delete bucket "${bucketToDelete ?? ''}". The bucket must be empty before it can be removed.`}
        confirmLabel="Delete bucket"
        confirmVariant="destructive"
        confirmationText={bucketToDelete ?? undefined}
        confirmationLabel="Bucket name"
        loading={deleteBucketMutation.isPending}
        onClose={() => setBucketToDelete(null)}
        onConfirm={confirmDeleteBucket}
      />
    </>
  )
}
