import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Check, Download, File as FileIcon, Folder, FolderPlus, History, Share2, Trash2, Upload } from 'lucide-react'
import { Fragment, useEffect, useRef, useState, type MouseEvent } from 'react'
import { Navigate, useNavigate, useParams, useSearchParams } from 'react-router'
import { ApiError } from '@/api/client'
import { objectKeys, settingsKeys } from '@/api/queryKeys'
import { Button } from '@/components/ui/button'
import { Callout } from '@/components/ui/callout'
import { ConfirmDialog } from '@/components/ui/confirm-dialog'
import { Dialog } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { getVersioning } from '@/features/settings/api'
import { VersionHistory } from '@/features/versions/VersionHistory'
import { formatDate, formatSize } from '@/lib/format'
import { bucketPath, displayName, downloadUrl, normalizePrefix } from '@/lib/paths'
import { toast } from '@/lib/toast'
import { createFolder, deleteObject, listObjects, presignObject, uploadObject } from './api'

const expiryOptions = [
  { label: '1 hour', seconds: 3600 },
  { label: '6 hours', seconds: 21600 },
  { label: '24 hours', seconds: 86400 },
  { label: '7 days', seconds: 604800 },
]

export function ObjectBrowserPage() {
  const { bucket } = useParams()
  if (!bucket) return <Navigate to="/" replace />
  return <ObjectBrowser key={bucket} bucket={bucket} />
}

function ObjectBrowser({ bucket }: { bucket: string }) {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [searchParams] = useSearchParams()
  const prefix = normalizePrefix(searchParams.get('prefix'))

  const fileInput = useRef<HTMLInputElement>(null)
  const createFolderInput = useRef<HTMLInputElement>(null)
  const [copiedKey, setCopiedKey] = useState<string | null>(null)
  const [shareMenu, setShareMenu] = useState<{ key: string; top: number; left: number } | null>(null)
  const [showCreateFolder, setShowCreateFolder] = useState(false)
  const [newFolderName, setNewFolderName] = useState('')
  const [versionKey, setVersionKey] = useState<string | null>(null)
  const [pendingDelete, setPendingDelete] = useState<{ key: string; kind: 'object' | 'folder' } | null>(null)

  const objectsQuery = useQuery({
    queryKey: objectKeys.list(bucket, prefix),
    queryFn: () => listObjects(bucket, prefix),
  })
  const versioningQuery = useQuery({
    queryKey: settingsKeys.versioning(bucket),
    queryFn: () => getVersioning(bucket),
  })

  const files = objectsQuery.data?.files ?? []
  const prefixes = objectsQuery.data?.prefixes ?? []
  const emptyPrefixes = new Set(objectsQuery.data?.emptyPrefixes ?? [])
  const versioningEnabled = !!versioningQuery.data?.enabled

  function refreshListing() {
    void queryClient.invalidateQueries({ queryKey: objectKeys.list(bucket, prefix) })
  }

  function resetFileInput() {
    if (fileInput.current) fileInput.current.value = ''
  }

  const uploadMutation = useMutation({
    mutationFn: async (selected: File[]) => {
      for (const file of selected) {
        await uploadObject(bucket, `${prefix}${file.name}`, file)
      }
      return selected.length
    },
    onSuccess: (count) => {
      toast.success(count === 1 ? 'File uploaded' : `${count} files uploaded`)
      resetFileInput()
      refreshListing()
    },
  })

  const deleteObjectMutation = useMutation({
    mutationFn: (key: string) => deleteObject(bucket, key),
    onSuccess: (_data, key) => {
      toast.success(`"${displayName(key)}" deleted`)
      refreshListing()
    },
  })

  const createFolderMutation = useMutation({
    mutationFn: (name: string) => createFolder(bucket, `${prefix}${name}`),
    onSuccess: (_data, name) => {
      toast.success(`Folder "${name}" created`)
      setNewFolderName('')
      setShowCreateFolder(false)
      refreshListing()
    },
  })

  useEffect(() => {
    if (!shareMenu) return
    const close = () => setShareMenu(null)
    document.addEventListener('click', close)
    return () => document.removeEventListener('click', close)
  }, [shareMenu])

  function navigateTo(nextPrefix: string) {
    navigate(bucketPath(bucket, nextPrefix))
  }

  async function handleUpload() {
    const selected = Array.from(fileInput.current?.files ?? [])
    if (selected.length === 0) return
    const toastId = toast.loading(
      selected.length === 1 ? `Uploading ${selected[0].name}…` : `Uploading ${selected.length} files…`,
    )
    try {
      await uploadMutation.mutateAsync(selected)
      toast.dismiss(toastId)
    } catch (err) {
      console.error('Upload failed:', err)
      toast.error(err instanceof Error ? err.message : 'Upload failed', { id: toastId })
      resetFileInput()
    }
  }

  async function confirmPendingDelete() {
    if (!pendingDelete) return
    const { key, kind } = pendingDelete
    try {
      await deleteObjectMutation.mutateAsync(key)
      setPendingDelete(null)
    } catch (err) {
      console.error(kind === 'folder' ? 'deleteFolder failed:' : 'deleteObject failed:', err)
      toast.error(
        err instanceof ApiError
          ? err.message
          : kind === 'folder'
            ? 'Failed to delete folder'
            : 'Failed to connect to server',
      )
    }
  }

  function toggleShareMenu(key: string, event: MouseEvent<HTMLButtonElement>) {
    event.stopPropagation()
    if (shareMenu?.key === key) {
      setShareMenu(null)
      return
    }
    const rect = event.currentTarget.getBoundingClientRect()
    setShareMenu({ key, top: rect.top, left: rect.right })
  }

  async function shareObject(key: string, expires: number) {
    setShareMenu(null)
    try {
      const data = await presignObject(bucket, key, expires)
      await navigator.clipboard.writeText(data.url)
      setCopiedKey(key)
      setTimeout(() => setCopiedKey(null), 2000)
      toast.success('Presigned URL copied to clipboard')
    } catch (err) {
      console.error('shareObject failed:', err)
      toast.error(err instanceof ApiError ? err.message : 'Failed to generate share link')
    }
  }

  function closeCreateFolder() {
    setShowCreateFolder(false)
    setNewFolderName('')
  }

  async function submitCreateFolder() {
    const name = newFolderName.trim()
    if (!name) return
    try {
      await createFolderMutation.mutateAsync(name)
    } catch (err) {
      console.error('createFolder failed:', err)
      toast.error(err instanceof ApiError ? err.message : 'Failed to create folder')
    }
  }

  return (
    <>
      <div className="flex flex-col gap-4">
        {objectsQuery.isError ? (
          <Callout type="danger">
            {objectsQuery.error instanceof ApiError ? objectsQuery.error.message : 'Failed to load objects'}
          </Callout>
        ) : null}

        <div className="flex items-center gap-2">
          <input
            ref={fileInput}
            type="file"
            multiple
            className="hidden"
            onChange={() => void handleUpload()}
            data-testid="upload-input"
          />
          <Button
            variant="highlighted"
            className="h-8"
            onClick={() => fileInput.current?.click()}
            disabled={uploadMutation.isPending}
          >
            <Upload className="size-4 mr-1" /> {uploadMutation.isPending ? 'Uploading...' : 'Upload'}
          </Button>
          <Button variant="outline" className="h-8" onClick={() => setShowCreateFolder(true)}>
            <FolderPlus className="size-4 mr-1" /> New Folder
          </Button>
        </div>

        {objectsQuery.isPending ? (
          <p className="text-sm text-muted-foreground">Loading...</p>
        ) : files.length === 0 && prefixes.length === 0 && !objectsQuery.isError ? (
          <Callout type="info">
            <span className="inline-flex items-center gap-2">
              <Folder className="size-4 opacity-70" />
              This location is empty — upload a file or create a folder to get started.
            </span>
          </Callout>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead className="w-28 text-right">Size</TableHead>
                <TableHead className="w-48">Modified</TableHead>
                <TableHead className="w-24"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {prefixes.map((folder) => (
                <TableRow key={folder} className="cursor-pointer" onClick={() => navigateTo(folder)}>
                  <TableCell>
                    <span className="flex items-center gap-2">
                      <Folder className="size-4 shrink-0 text-muted-foreground" />
                      <span className="font-medium">{displayName(folder)}/</span>
                    </span>
                  </TableCell>
                  <TableCell className="text-right text-muted-foreground">&mdash;</TableCell>
                  <TableCell className="text-muted-foreground">&mdash;</TableCell>
                  <TableCell>
                    {emptyPrefixes.has(folder) ? (
                      <button
                        type="button"
                        className="text-muted-foreground hover:text-destructive transition-colors"
                        onClick={(event) => {
                          event.stopPropagation()
                          setPendingDelete({ key: folder, kind: 'folder' })
                        }}
                        title="Delete empty folder"
                        aria-label="Delete empty folder"
                      >
                        <Trash2 className="size-4" />
                      </button>
                    ) : null}
                  </TableCell>
                </TableRow>
              ))}
              {files.map((file) => (
                <Fragment key={file.key}>
                  <TableRow>
                    <TableCell>
                      <span className="flex items-center gap-2">
                        <FileIcon className="size-4 shrink-0 text-muted-foreground" />
                        <span className="font-medium">{displayName(file.key)}</span>
                      </span>
                    </TableCell>
                    <TableCell className="text-right text-muted-foreground">{formatSize(file.size)}</TableCell>
                    <TableCell className="text-muted-foreground">{formatDate(file.lastModified)}</TableCell>
                    <TableCell className="w-24">
                      <span className="flex items-center gap-4">
                        {versioningEnabled ? (
                          <button
                            type="button"
                            className="text-muted-foreground hover:text-foreground transition-colors"
                            onClick={(event) => {
                              event.stopPropagation()
                              setVersionKey((current) => (current === file.key ? null : file.key))
                            }}
                            title="Version history"
                            aria-label="Version history"
                          >
                            <History className="size-4" />
                          </button>
                        ) : null}
                        <button
                          type="button"
                          className="text-muted-foreground hover:text-foreground transition-colors"
                          onClick={(event) => toggleShareMenu(file.key, event)}
                          title="Copy presigned URL"
                          aria-label="Copy presigned URL"
                        >
                          {copiedKey === file.key ? (
                            <Check className="size-4 text-green-500" />
                          ) : (
                            <Share2 className="size-4" />
                          )}
                        </button>
                        <a
                          href={downloadUrl(bucket, file.key)}
                          className="text-muted-foreground hover:text-foreground"
                          onClick={(event) => event.stopPropagation()}
                          title="Download"
                          aria-label="Download"
                        >
                          <Download className="size-4" />
                        </a>
                        <button
                          type="button"
                          className="text-muted-foreground hover:text-destructive transition-colors"
                          onClick={(event) => {
                            event.stopPropagation()
                            setPendingDelete({ key: file.key, kind: 'object' })
                          }}
                          title="Delete"
                          aria-label="Delete"
                        >
                          <Trash2 className="size-4" />
                        </button>
                      </span>
                    </TableCell>
                  </TableRow>
                  {versionKey === file.key ? (
                    <TableRow>
                      <TableCell colSpan={4} className="p-0">
                        <div className="p-2">
                          <VersionHistory
                            bucket={bucket}
                            objectKey={file.key}
                            onClose={() => setVersionKey(null)}
                            onVersionDeleted={refreshListing}
                          />
                        </div>
                      </TableCell>
                    </TableRow>
                  ) : null}
                </Fragment>
              ))}
            </TableBody>
          </Table>
        )}
      </div>

      <Dialog
        open={showCreateFolder}
        title="Create folder"
        description="Create an empty folder marker in the current location."
        loading={createFolderMutation.isPending}
        onClose={closeCreateFolder}
        initialFocus={createFolderInput}
        footer={
          <>
            <Button variant="default" disabled={createFolderMutation.isPending} onClick={closeCreateFolder}>
              Cancel
            </Button>
            <Button
              type="submit"
              form="create-folder-form"
              variant="highlighted"
              disabled={createFolderMutation.isPending || !newFolderName.trim()}
            >
              {createFolderMutation.isPending ? 'Creating…' : 'Create folder'}
            </Button>
          </>
        }
      >
        <form
          id="create-folder-form"
          onSubmit={(event) => {
            event.preventDefault()
            void submitCreateFolder()
          }}
          className="flex flex-col gap-1.5"
        >
          <label htmlFor="folder-name" className="text-sm font-medium text-black dark:text-white">
            Folder name
          </label>
          <Input
            ref={createFolderInput}
            id="folder-name"
            type="text"
            value={newFolderName}
            onChange={(event) => setNewFolderName(event.target.value)}
            placeholder="folder-name"
            className="bg-white dark:bg-base"
            disabled={createFolderMutation.isPending}
          />
        </form>
      </Dialog>

      {shareMenu ? (
        <div
          className="fixed z-50 min-w-[8rem] rounded-sm border bg-popover p-1 shadow-md"
          style={{ top: shareMenu.top, left: shareMenu.left, transform: 'translate(-100%, -100%)' }}
          role="menu"
        >
          {expiryOptions.map((option) => (
            <button
              key={option.seconds}
              type="button"
              role="menuitem"
              className="w-full rounded-sm px-2 py-1.5 text-left text-sm text-popover-foreground hover:bg-accent hover:text-accent-foreground"
              onClick={() => void shareObject(shareMenu.key, option.seconds)}
            >
              {option.label}
            </button>
          ))}
        </div>
      ) : null}

      {pendingDelete ? (
        <ConfirmDialog
          open
          title={pendingDelete.kind === 'folder' ? 'Delete empty folder?' : 'Delete object?'}
          description={
            pendingDelete.kind === 'folder'
              ? `This will remove the empty folder marker "${displayName(pendingDelete.key)}".`
              : `This will delete "${displayName(pendingDelete.key)}" from this bucket.`
          }
          confirmLabel={pendingDelete.kind === 'folder' ? 'Delete folder' : 'Delete object'}
          confirmVariant="destructive"
          loading={deleteObjectMutation.isPending}
          onClose={() => setPendingDelete(null)}
          onConfirm={confirmPendingDelete}
        />
      ) : null}
    </>
  )
}
