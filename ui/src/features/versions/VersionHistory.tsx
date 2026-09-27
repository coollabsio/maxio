import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Download, LoaderCircle, Tag, Trash2 } from 'lucide-react'
import { useState } from 'react'
import { ApiError } from '@/api/client'
import { versionKeys } from '@/api/queryKeys'
import { Button } from '@/components/ui/button'
import { Callout } from '@/components/ui/callout'
import { ConfirmDialog } from '@/components/ui/confirm-dialog'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { formatDate, formatVersionSize, truncateId } from '@/lib/format'
import { versionDownloadUrl } from '@/lib/paths'
import { deleteVersion, listVersions } from './api'

interface VersionHistoryProps {
  bucket: string
  objectKey: string
  onClose: () => void
  onVersionDeleted?: () => void
}

/** Inline panel listing every version of one object (shown under its row in the object browser). */
export function VersionHistory({ bucket, objectKey, onClose, onVersionDeleted }: VersionHistoryProps) {
  const queryClient = useQueryClient()
  const [deleteError, setDeleteError] = useState<string | null>(null)
  const [versionToDelete, setVersionToDelete] = useState<string | null>(null)

  const versionsQuery = useQuery({
    queryKey: versionKeys.list(bucket, objectKey),
    queryFn: () => listVersions(bucket, objectKey),
  })
  const versions = versionsQuery.data?.versions ?? []

  const deleteVersionMutation = useMutation({
    mutationFn: (versionId: string) => deleteVersion(bucket, objectKey, versionId),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: versionKeys.list(bucket, objectKey) })
      onVersionDeleted?.()
    },
  })

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
      <div className="rounded-sm border bg-card">
        <div className="flex items-center justify-between border-b px-4 py-2">
          <h4 className="text-sm font-semibold">Version History</h4>
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
                <TableHead className="w-20"></TableHead>
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
                      <span className="ml-1 rounded-sm bg-accent/20 px-1 py-0.5 text-[10px] font-medium text-accent-foreground">
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
                      <span className="inline-flex items-center gap-1 rounded-sm bg-destructive/10 px-1.5 py-0.5 text-[10px] font-medium text-destructive">
                        <Tag className="size-3" /> Delete Marker
                      </span>
                    ) : (
                      <span className="text-xs text-muted-foreground">Version</span>
                    )}
                  </TableCell>
                  <TableCell className="w-20">
                    <div className="flex items-center gap-4">
                      {!version.isDeleteMarker && version.versionId ? (
                        // The server sends `Content-Disposition: attachment`, so a plain link downloads without a popup.
                        <a
                          href={versionDownloadUrl(bucket, objectKey, version.versionId)}
                          className="text-muted-foreground hover:text-foreground transition-colors"
                          title="Download this version"
                          aria-label="Download this version"
                        >
                          <Download className="size-4" />
                        </a>
                      ) : null}
                      {version.versionId ? (
                        <button
                          type="button"
                          className="text-muted-foreground hover:text-destructive transition-colors"
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
