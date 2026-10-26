import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Download, LoaderCircle, RotateCcw, Tag, Trash2 } from 'lucide-react'
import { useState } from 'react'
import { ApiError } from '@/api/client'
import { objectKeys, versionKeys } from '@/api/queryKeys'
import { Button } from '@/components/ui/button'
import { Callout } from '@/components/ui/callout'
import { ConfirmDialog } from '@/components/ui/confirm-dialog'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { downloadObjectFile } from '@/features/objects/download'
import { formatDate, formatVersionSize, truncateId } from '@/lib/format'
import { toast } from '@/lib/toast'
import { deleteVersion, listVersions, restoreVersion } from './api'

interface VersionHistoryProps {
  bucket: string
  objectKey: string
  onClose: () => void
  /** Called after a version was deleted or restored (the object listing may have changed). */
  onVersionsChanged?: () => void
}

/** Inline panel listing every version of one object (shown under its row in the object browser). */
export function VersionHistory({ bucket, objectKey, onClose, onVersionsChanged }: VersionHistoryProps) {
  const queryClient = useQueryClient()
  const [deleteError, setDeleteError] = useState<string | null>(null)
  const [versionToDelete, setVersionToDelete] = useState<string | null>(null)
  const [versionToRestore, setVersionToRestore] = useState<string | null>(null)

  const versionsQuery = useQuery({
    queryKey: versionKeys.list(bucket, objectKey),
    queryFn: () => listVersions(bucket, objectKey),
  })
  const versions = versionsQuery.data?.versions ?? []

  const deleteVersionMutation = useMutation({
    mutationFn: (versionId: string) => deleteVersion(bucket, objectKey, versionId),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: versionKeys.list(bucket, objectKey) })
      onVersionsChanged?.()
    },
  })

  const restoreVersionMutation = useMutation({
    mutationFn: (versionId: string) => restoreVersion(bucket, objectKey, versionId),
    onSuccess: () => {
      toast.success('Version restored as the current version')
      void queryClient.invalidateQueries({ queryKey: versionKeys.list(bucket, objectKey) })
      void queryClient.invalidateQueries({ queryKey: objectKeys.info(bucket, objectKey) })
      onVersionsChanged?.()
    },
  })

  async function confirmRestoreVersion() {
    if (!versionToRestore) return
    try {
      await restoreVersionMutation.mutateAsync(versionToRestore)
      setVersionToRestore(null)
    } catch (err) {
      console.error('restoreVersion failed:', err)
      toast.error(err instanceof ApiError ? err.message : 'Failed to restore version')
    }
  }

  async function confirmDeleteVersion() {
    if (!versionToDelete) return
    try {
      setDeleteError(null)
      await deleteVersionMutation.mutateAsync(versionToDelete)
      setVersionToDelete(null)
    } catch (err) {
      console.error('deleteVersion failed:', err)
      setDeleteError(err instanceof ApiError ? err.message : 'Failed to connect to server')
    }
  }

  return (
    <>
      <div className="overflow-hidden rounded-lg border border-neutral-200 bg-neutral-50 dark:border-white/[0.08] dark:bg-white/[0.02]">
        <div className="flex items-center justify-between border-b px-4 py-2">
          <h4 className="text-[13px] font-medium text-black dark:text-fg">Version History</h4>
          <Button variant="ghost" size="sm" onClick={onClose}>
            Close
          </Button>
        </div>

        {versionsQuery.isError || deleteError ? (
          <div className="p-4">
            <Callout type="danger">
              {deleteError ??
                (versionsQuery.error instanceof ApiError ? versionsQuery.error.message : 'Failed to load versions')}
            </Callout>
          </div>
        ) : null}

        {versionsQuery.isPending ? (
          <div className="flex items-center gap-2 px-4 py-4 text-sm text-muted-foreground">
            <LoaderCircle className="size-4 animate-spin" /> Loading versions...
          </div>
        ) : versions.length === 0 ? (
          <div className="px-4 py-4 text-sm text-muted-foreground">No versions found.</div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Version ID</TableHead>
                <TableHead>Date</TableHead>
                <TableHead>Size</TableHead>
                <TableHead>Type</TableHead>
                <TableHead className="hidden lg:table-cell">ETag</TableHead>
                <TableHead className="w-28"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {versions.map((version, index) => (
                <TableRow key={version.versionId ?? `null-${index}`} className={version.isDeleteMarker ? 'opacity-60' : ''}>
                  <TableCell className="font-mono text-xs">
                    <span title={version.versionId ?? ''}>
                      {version.versionId ? truncateId(version.versionId) : 'null'}
                    </span>
                    {index === 0 ? (
                      <span className="ml-1 rounded-md bg-brand/10 px-1.5 py-0.5 text-[10px] font-medium text-brand dark:bg-brand/15 dark:text-brand-light">
                        latest
                      </span>
                    ) : null}
                  </TableCell>
                  <TableCell className="text-muted-foreground text-xs">{formatDate(version.lastModified)}</TableCell>
                  <TableCell className="text-muted-foreground text-xs">
                    {version.isDeleteMarker ? '—' : formatVersionSize(version.size)}
                  </TableCell>
                  <TableCell>
                    {version.isDeleteMarker ? (
                      <span className="inline-flex items-center gap-1 rounded-md bg-destructive/10 px-1.5 py-0.5 text-[10px] font-medium text-destructive">
                        <Tag className="size-3" /> Delete Marker
                      </span>
                    ) : (
                      <span className="text-xs text-muted-foreground">Version</span>
                    )}
                  </TableCell>
                  <TableCell className="hidden font-mono text-xs text-muted-foreground lg:table-cell">
                    {version.isDeleteMarker ? (
                      '—'
                    ) : (
                      <span title={version.etag}>{truncateId(version.etag.replaceAll('"', ''))}</span>
                    )}
                  </TableCell>
                  <TableCell className="w-28">
                    <div className="flex items-center justify-end gap-1">
                      {index > 0 && !version.isDeleteMarker && version.versionId ? (
                        <button
                          type="button"
                          className="icon-button"
                          onClick={() => setVersionToRestore(version.versionId)}
                          title="Restore this version"
                          aria-label="Restore this version"
                        >
                          <RotateCcw className="size-4" />
                        </button>
                      ) : null}
                      {!version.isDeleteMarker && version.versionId ? (
                        <button
                          type="button"
                          className="icon-button"
                          title="Download this version"
                          aria-label="Download this version"
                          onClick={() => {
                            const versionId = version.versionId
                            if (!versionId) return
                            void downloadObjectFile(bucket, objectKey, versionId).catch((err: unknown) => {
                              console.error('version download failed:', err)
                              toast.error(err instanceof ApiError ? err.message : 'Download failed')
                            })
                          }}
                        >
                          <Download className="size-4" />
                        </button>
                      ) : null}
                      {version.versionId ? (
                        <button
                          type="button"
                          className="icon-button hover:!text-error"
                          onClick={() => setVersionToDelete(version.versionId)}
                          title="Permanently delete this version"
                          aria-label="Permanently delete this version"
                        >
                          <Trash2 className="size-4" />
                        </button>
                      ) : null}
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </div>

      <ConfirmDialog
        open={versionToRestore !== null}
        title="Restore this version?"
        description="A copy of this version becomes the new current version. All existing versions are kept."
        confirmLabel="Restore version"
        loading={restoreVersionMutation.isPending}
        onClose={() => setVersionToRestore(null)}
        onConfirm={confirmRestoreVersion}
      />

      <ConfirmDialog
        open={versionToDelete !== null}
        title="Permanently delete version?"
        description="This object version will be permanently deleted. This cannot be undone."
        confirmLabel="Delete version"
        confirmVariant="destructive"
        confirmationText="delete"
        confirmationLabel="Type delete"
        loading={deleteVersionMutation.isPending}
        onClose={() => setVersionToDelete(null)}
        onConfirm={confirmDeleteVersion}
      />
    </>
  )
}
