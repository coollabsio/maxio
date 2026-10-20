import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Check,
  Download,
  File as FileIcon,
  Folder,
  FolderPlus,
  History,
  Info,
  Settings,
  Share2,
  Trash2,
  Upload,
} from 'lucide-react'
import { Fragment, useEffect, useRef, useState, type MouseEvent } from 'react'
import { Navigate, useNavigate, useParams, useSearchParams } from 'react-router'
import { ApiError } from '@/api/client'
import { objectKeys, settingsKeys } from '@/api/queryKeys'
import { Button } from '@/components/ui/button'
import { Callout } from '@/components/ui/callout'
import { ConfirmDialog } from '@/components/ui/confirm-dialog'
import { Dialog } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { PageHeader } from '@/components/ui/page-header'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { getVersioning } from '@/features/settings/api'
import { VersionHistory } from '@/features/versions/VersionHistory'
import { formatDate, formatSize } from '@/lib/format'
import { bucketPath, bucketSettingsPath, displayName, normalizePrefix } from '@/lib/paths'
import { toast } from '@/lib/toast'
import { createFolder, deleteObject, getCapabilities, listObjects, presignObject, uploadObject } from './api'
import { downloadObjectFile } from './download'
import { ObjectDetailsSheet } from './ObjectDetailsSheet'

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
  const [detailsKey, setDetailsKey] = useState<string | null>(null)
  const [pendingDelete, setPendingDelete] = useState<{ key: string; kind: 'object' | 'folder' } | null>(null)

  const objectsQuery = useQuery({
    queryKey: objectKeys.list(bucket, prefix),
    queryFn: () => listObjects(bucket, prefix),
  })
  const versioningQuery = useQuery({
    queryKey: settingsKeys.versioning(bucket),
    queryFn: () => getVersioning(bucket),
  })
  const capabilitiesQuery = useQuery({
    queryKey: ['capabilities', bucket, prefix],
    queryFn: () => getCapabilities(bucket, prefix),
  })
  const canWrite = capabilitiesQuery.data?.putObject === true
  const canDelete = capabilitiesQuery.data?.deleteObject === true

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

  async function downloadFile(key: string) {
    try {
      await downloadObjectFile(bucket, key)
    } catch (err) {
      console.error('download failed:', err)
      toast.error(err instanceof ApiError ? err.message : 'Download failed')
    }
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
      <div className="flex flex-col gap-6">
        <PageHeader
          title={prefix ? `${displayName(prefix)}/` : bucket}
          description={prefix ? `${bucket}/${prefix}` : 'Files and folders in this bucket'}
          actions={
            <>
              <Button
                variant="ghost"
                size="icon"
                onClick={() => navigate(bucketSettingsPath(bucket))}
                title="Bucket settings"
                aria-label="Open bucket settings"
              >
                <Settings />
              </Button>
              {canWrite ? (
                <Button variant="default" onClick={() => setShowCreateFolder(true)}>
                  <FolderPlus /> New Folder
                </Button>
              ) : null}
              {canWrite ? (
                <Button
                  variant="highlighted"
                  onClick={() => fileInput.current?.click()}
                  disabled={uploadMutation.isPending}
                >
                  <Upload /> {uploadMutation.isPending ? 'Uploading...' : 'Upload'}
                </Button>
              ) : null}
            </>
          }
        />

        {objectsQuery.isError ? (
          <Callout type="danger">
            {objectsQuery.error instanceof ApiError ? objectsQuery.error.message : 'Failed to load objects'}
          </Callout>
        ) : null}

        <input
          ref={fileInput}
          type="file"
          multiple
          className="hidden"
          onChange={() => void handleUpload()}
          data-testid="upload-input"
        />

        {objectsQuery.isPending ? (
          <p className="text-sm text-muted-foreground">Loading...</p>
        ) : files.length === 0 && prefixes.length === 0 && !objectsQuery.isError ? (
          <Callout type="info">
            <span className="inline-flex items-center gap-2">
              <Folder className="size-4 opacity-70" />
              {canWrite
                ? 'This location is empty — upload a file or create a folder to get started.'
                : 'This location is empty.'}
            </span>
          </Callout>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead className="hidden w-48 xl:table-cell">Type</TableHead>
                <TableHead className="w-28 text-right">Size</TableHead>
                <TableHead className="w-48">Modified</TableHead>
                <TableHead className="w-32"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {prefixes.map((folder) => (
                <TableRow key={folder} className="cursor-pointer" onClick={() => navigateTo(folder)}>
                  <TableCell>
                    <span className="flex items-center gap-2">
                      <Folder className="size-4 shrink-0 text-coollabs dark:text-warning" />
                      <span className="font-semibold">{displayName(folder)}/</span>
                    </span>
                  </TableCell>
                  <TableCell className="hidden text-muted-foreground xl:table-cell">&mdash;</TableCell>
                  <TableCell className="text-right text-muted-foreground">&mdash;</TableCell>
                  <TableCell className="text-muted-foreground">&mdash;</TableCell>
                  <TableCell className="text-right">
                    {canDelete && emptyPrefixes.has(folder) ? (
                      <button
                        type="button"
                        className="icon-button hover:!text-error"
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
                  <TableRow className="cursor-pointer" onClick={() => setDetailsKey(file.key)}>
                    <TableCell>
                      <span className="flex items-center gap-2">
                        <FileIcon className="size-4 shrink-0 text-muted-foreground" />
                        <span className="font-medium">{displayName(file.key)}</span>
                      </span>
                    </TableCell>
                    <TableCell className="hidden max-w-48 truncate text-xs text-muted-foreground xl:table-cell">
                      {file.contentType}
                    </TableCell>
                    <TableCell className="text-right text-muted-foreground">{formatSize(file.size)}</TableCell>
                    <TableCell className="text-muted-foreground">{formatDate(file.lastModified)}</TableCell>
                    <TableCell className="w-32">
                      <span className="flex items-center justify-end gap-1">
                        <button
                          type="button"
                          className="icon-button"
                          onClick={(event) => {
                            event.stopPropagation()
                            setDetailsKey(file.key)
                          }}
                          title="Details"
                          aria-label="Details"
                        >
                          <Info className="size-4" />
                        </button>
                        {versioningEnabled ? (
                          <button
                            type="button"
                            className="icon-button"
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
                          className="icon-button"
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
                        <button
                          type="button"
                          className="icon-button"
                          onClick={(event) => {
                            event.stopPropagation()
                            void downloadFile(file.key)
                          }}
                          title="Download"
                          aria-label="Download"
                        >
                          <Download className="size-4" />
                        </button>
                        {canDelete ? (
                          <button
                            type="button"
                            className="icon-button hover:!text-error"
                            onClick={(event) => {
                              event.stopPropagation()
                              setPendingDelete({ key: file.key, kind: 'object' })
                            }}
                            title="Delete"
                            aria-label="Delete"
                          >
                            <Trash2 className="size-4" />
                          </button>
                        ) : null}
                      </span>
                    </TableCell>
                  </TableRow>
                  {versionKey === file.key ? (
                    <TableRow>
                      <TableCell colSpan={5} className="p-0">
                        <div className="p-2">
                          <VersionHistory
                            bucket={bucket}
                            objectKey={file.key}
                            onClose={() => setVersionKey(null)}
                            onVersionsChanged={refreshListing}
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
          <label htmlFor="folder-name" className="text-[13px] font-medium text-black dark:text-fg">
            Folder name
          </label>
          <Input
            ref={createFolderInput}
            id="folder-name"
            type="text"
            value={newFolderName}
            onChange={(event) => setNewFolderName(event.target.value)}
            placeholder="folder-name"
            disabled={createFolderMutation.isPending}
          />
        </form>
      </Dialog>

      {shareMenu ? (
        <div
          className="fixed z-50 flex min-w-[8rem] flex-col gap-px rounded-[10px] border border-line bg-white p-1 shadow-dropdown dark:bg-coolgray-200"
          style={{ top: shareMenu.top, left: shareMenu.left, transform: 'translate(-100%, -100%)' }}
          role="menu"
        >
          {expiryOptions.map((option) => (
            <button
              key={option.seconds}
              type="button"
              role="menuitem"
              className="w-full rounded-md px-2 py-1.5 text-left text-[13px] text-black hover:bg-fill dark:text-fg"
              onClick={() => void shareObject(shareMenu.key, option.seconds)}
            >
              {option.label}
            </button>
          ))}
        </div>
      ) : null}

      <ObjectDetailsSheet bucket={bucket} objectKey={detailsKey} onClose={() => setDetailsKey(null)} />

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
