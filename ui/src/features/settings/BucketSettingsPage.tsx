import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Navigate, useParams } from 'react-router'
import { ApiError } from '@/api/client'
import { bucketKeys, settingsKeys } from '@/api/queryKeys'
import { Callout } from '@/components/ui/callout'
import { ConfirmDialog } from '@/components/ui/confirm-dialog'
import { Switch } from '@/components/ui/switch'
import { toast } from '@/lib/toast'
import { getEncryption, getPublicAccess, getVersioning, setEncryption, setPublicAccess, setVersioning } from './api'

interface PendingConfirmation {
  title: string
  description: string
  confirmLabel: string
  destructive?: boolean
  action: () => Promise<void>
}

interface SettingRowProps {
  title: string
  description: string
  loading: boolean
  checked: boolean
  disabled: boolean
  label: string
  onToggle: () => void
}

function SettingRow({ title, description, loading, checked, disabled, label, onToggle }: SettingRowProps) {
  return (
    <div className="flex items-center justify-between">
      <div className="flex flex-col gap-0.5">
        <span className="text-sm font-medium">{title}</span>
        <span className="text-sm text-muted-foreground">{loading ? 'Loading...' : description}</span>
      </div>
      {!loading ? (
        <Switch checked={checked} onCheckedChange={onToggle} disabled={disabled} aria-label={label} />
      ) : null}
    </div>
  )
}

export function BucketSettingsPage() {
  const { bucket } = useParams()
  if (!bucket) return <Navigate to="/" replace />
  return <BucketSettings key={bucket} bucket={bucket} />
}

function BucketSettings({ bucket }: { bucket: string }) {
  const queryClient = useQueryClient()
  const [pendingConfirmation, setPendingConfirmation] = useState<PendingConfirmation | null>(null)

  const versioningQuery = useQuery({ queryKey: settingsKeys.versioning(bucket), queryFn: () => getVersioning(bucket) })
  const encryptionQuery = useQuery({ queryKey: settingsKeys.encryption(bucket), queryFn: () => getEncryption(bucket) })
  const publicQuery = useQuery({ queryKey: settingsKeys.publicAccess(bucket), queryFn: () => getPublicAccess(bucket) })

  const versioningEnabled = !!versioningQuery.data?.enabled
  const encryptionEnabled = !!encryptionQuery.data?.enabled
  const publicRead = !!publicQuery.data?.read
  const publicList = !!publicQuery.data?.list

  const versioningMutation = useMutation({
    mutationFn: (enabled: boolean) => setVersioning(bucket, enabled),
    onSuccess: (_data, enabled) => {
      toast.success(enabled ? 'Versioning enabled' : 'Versioning disabled')
      void queryClient.invalidateQueries({ queryKey: settingsKeys.versioning(bucket) })
      void queryClient.invalidateQueries({ queryKey: bucketKeys.list() })
    },
  })

  const encryptionMutation = useMutation({
    mutationFn: (enabled: boolean) => setEncryption(bucket, enabled),
    onSuccess: (_data, enabled) => {
      toast.success(enabled ? 'Default encryption enabled' : 'Default encryption disabled')
      void queryClient.invalidateQueries({ queryKey: settingsKeys.encryption(bucket) })
      void queryClient.invalidateQueries({ queryKey: bucketKeys.list() })
    },
  })

  const publicMutation = useMutation({
    mutationFn: (next: { read: boolean; list: boolean }) => setPublicAccess(bucket, next.read, next.list),
    onSuccess: (_data, next) => {
      void queryClient.invalidateQueries({ queryKey: settingsKeys.publicAccess(bucket) })
      toast.success(
        next.read !== publicRead
          ? next.read
            ? 'Public read enabled'
            : 'Public read disabled'
          : next.list
            ? 'Public listing enabled'
            : 'Public listing disabled',
      )
    },
  })

  async function applyVersioning(enabled: boolean) {
    try {
      await versioningMutation.mutateAsync(enabled)
      setPendingConfirmation(null)
    } catch (err) {
      console.error('toggleVersioning failed:', err)
      toast.error(err instanceof ApiError ? err.message : 'Failed to update versioning')
    }
  }

  async function applyEncryption(enabled: boolean) {
    try {
      await encryptionMutation.mutateAsync(enabled)
      setPendingConfirmation(null)
    } catch (err) {
      console.error('toggleEncryption failed:', err)
      toast.error(err instanceof ApiError ? err.message : 'Failed to update encryption')
    }
  }

  async function applyPublicAccess(next: { read: boolean; list: boolean }) {
    try {
      await publicMutation.mutateAsync(next)
      setPendingConfirmation(null)
    } catch (err) {
      console.error('togglePublicRead failed:', err)
      toast.error(err instanceof ApiError ? err.message : 'Failed to update public access')
    }
  }

  function toggleVersioning() {
    if (versioningEnabled) {
      setPendingConfirmation({
        title: 'Disable versioning?',
        description:
          'This will permanently delete all old versions. Only the latest version of each file will be kept. This cannot be undone.',
        confirmLabel: 'Disable versioning',
        destructive: true,
        action: () => applyVersioning(false),
      })
      return
    }
    void applyVersioning(true)
  }

  function toggleEncryption() {
    if (encryptionEnabled) {
      setPendingConfirmation({
        title: 'Disable default encryption?',
        description: 'New uploads will be stored unencrypted. Existing encrypted objects stay encrypted.',
        confirmLabel: 'Disable encryption',
        destructive: true,
        action: () => applyEncryption(false),
      })
      return
    }
    void applyEncryption(true)
  }

  function togglePublicRead() {
    if (!publicRead) {
      setPendingConfirmation({
        title: 'Enable public read?',
        description:
          'Anyone with a URL to an object in this bucket can download it without credentials. Only enable if every object in the bucket is safe to share publicly.',
        confirmLabel: 'Enable public read',
        action: () => applyPublicAccess({ read: true, list: publicList }),
      })
      return
    }
    void applyPublicAccess({ read: false, list: publicList })
  }

  function togglePublicList() {
    if (!publicList) {
      setPendingConfirmation({
        title: 'Enable public listing?',
        description:
          'Anyone can list every object key in this bucket without credentials. Keys may reveal sensitive structure.',
        confirmLabel: 'Enable public listing',
        action: () => applyPublicAccess({ read: publicRead, list: true }),
      })
      return
    }
    void applyPublicAccess({ read: publicRead, list: false })
  }

  return (
    <>
      <div className="flex flex-col gap-6 max-w-2xl">
        {versioningQuery.isError || encryptionQuery.isError || publicQuery.isError ? (
          <Callout type="danger">Failed to load bucket settings</Callout>
        ) : null}

        {versioningEnabled && !versioningQuery.isPending ? (
          <Callout type="warning" title="Disabling versioning is destructive">
            Turning versioning off permanently deletes all non-current versions. Only the latest version of each object
            remains.
          </Callout>
        ) : null}

        <div className="flex flex-col gap-4">
          <h3 className="text-sm font-medium text-muted-foreground uppercase tracking-wide">General</h3>

          <SettingRow
            title="Versioning"
            loading={versioningQuery.isPending}
            description={
              versioningEnabled
                ? 'Every upload creates a new version. Deleted files become delete markers.'
                : 'Uploading a file overwrites the previous version.'
            }
            checked={versioningEnabled}
            disabled={versioningMutation.isPending}
            label="Toggle versioning"
            onToggle={toggleVersioning}
          />

          <SettingRow
            title="Default encryption (SSE-S3)"
            loading={encryptionQuery.isPending}
            description={
              encryptionEnabled
                ? 'New uploads are encrypted at rest with SSE-S3 (AES-256).'
                : 'New uploads are stored unencrypted unless the client sends SSE headers.'
            }
            checked={encryptionEnabled}
            disabled={encryptionMutation.isPending}
            label="Toggle default encryption"
            onToggle={toggleEncryption}
          />

          <SettingRow
            title="Public read"
            loading={publicQuery.isPending}
            description={
              publicRead
                ? 'Anyone with an object URL can download it without credentials.'
                : 'Object downloads require a signed request.'
            }
            checked={publicRead}
            disabled={publicMutation.isPending}
            label="Toggle public read"
            onToggle={togglePublicRead}
          />

          <SettingRow
            title="Public listing"
            loading={publicQuery.isPending}
            description={
              publicList
                ? 'Anyone can list every object key in this bucket without credentials.'
                : 'Listing the bucket requires a signed request.'
            }
            checked={publicList}
            disabled={publicMutation.isPending}
            label="Toggle public listing"
            onToggle={togglePublicList}
          />
        </div>
      </div>

      {pendingConfirmation ? (
        <ConfirmDialog
          open
          title={pendingConfirmation.title}
          description={pendingConfirmation.description}
          confirmLabel={pendingConfirmation.confirmLabel}
          confirmVariant={pendingConfirmation.destructive ? 'destructive' : 'highlighted'}
          loading={versioningMutation.isPending || encryptionMutation.isPending || publicMutation.isPending}
          onClose={() => setPendingConfirmation(null)}
          onConfirm={pendingConfirmation.action}
        />
      ) : null}
    </>
  )
}
