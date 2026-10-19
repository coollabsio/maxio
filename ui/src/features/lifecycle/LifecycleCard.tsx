import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Pencil, Plus, Trash2 } from 'lucide-react'
import { useState } from 'react'
import { ApiError } from '@/api/client'
import { settingsKeys } from '@/api/queryKeys'
import type { LifecycleRule } from '@/api/generated/types.gen'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Callout } from '@/components/ui/callout'
import { ConfirmDialog } from '@/components/ui/confirm-dialog'
import { toast } from '@/lib/toast'
import { getBucketLifecycle, setBucketLifecycle } from './api'
import { LifecycleRuleDialog } from './LifecycleRuleDialog'
import { summarizeActions, summarizeFilter, usesNoncurrentVersions } from './rules'

/** `index` is the rule being edited, `null` adds a new rule. */
type Editing = { index: number | null } | null

export function LifecycleCard({ bucket, versioningEnabled }: { bucket: string; versioningEnabled: boolean }) {
  const queryClient = useQueryClient()
  const [editing, setEditing] = useState<Editing>(null)
  const [deleteIndex, setDeleteIndex] = useState<number | null>(null)

  const lifecycleQuery = useQuery({
    queryKey: settingsKeys.lifecycle(bucket),
    queryFn: () => getBucketLifecycle(bucket),
  })
  const rules = lifecycleQuery.data?.rules ?? []

  // Every change saves the whole rule set; the server validates it and returns the stored (normalized) rules.
  const mutation = useMutation({
    mutationFn: (next: LifecycleRule[]) => setBucketLifecycle(bucket, next),
    onSuccess: (data) => {
      queryClient.setQueryData(settingsKeys.lifecycle(bucket), data)
    },
  })

  async function save(next: LifecycleRule[], message: string) {
    try {
      await mutation.mutateAsync(next)
      toast.success(message)
      return true
    } catch (err) {
      console.error('setBucketLifecycle failed:', err)
      toast.error(err instanceof ApiError ? err.message : 'Failed to save lifecycle rules')
      return false
    }
  }

  async function saveRule(rule: LifecycleRule) {
    if (!editing) return
    const next =
      editing.index === null ? [...rules, rule] : rules.map((current, i) => (i === editing.index ? rule : current))
    if (await save(next, editing.index === null ? 'Lifecycle rule added' : 'Lifecycle rule updated')) setEditing(null)
  }

  async function deleteRule() {
    if (deleteIndex === null) return
    if (await save(rules.filter((_, i) => i !== deleteIndex), 'Lifecycle rule deleted')) setDeleteIndex(null)
  }

  const needsVersioning = !versioningEnabled && rules.some(usesNoncurrentVersions)

  return (
    <>
      <section className="settings-section">
        <div className="settings-section-header">
          <div className="flex items-center justify-between gap-4">
            <div>
              <h2>Lifecycle rules</h2>
              <p>Expire objects, clean up old versions and abandoned multipart uploads automatically.</p>
            </div>
            <Button variant="default" size="sm" onClick={() => setEditing({ index: null })} disabled={lifecycleQuery.isPending}>
              <Plus /> Add rule
            </Button>
          </div>
        </div>
        <div className="settings-section-body">
          {lifecycleQuery.isPending ? (
            <p className="px-4 py-3.5 text-[13px] text-neutral-500 dark:text-fg-faint">Loading...</p>
          ) : lifecycleQuery.isError ? (
            <div className="p-4">
              <Callout type="danger">
                {lifecycleQuery.error instanceof ApiError ? lifecycleQuery.error.message : 'Failed to load lifecycle rules'}
              </Callout>
            </div>
          ) : rules.length === 0 ? (
            <p className="px-4 py-3.5 text-[13px] text-neutral-500 dark:text-fg-faint">No lifecycle rules.</p>
          ) : (
            <ul className="divide-y divide-neutral-200 dark:divide-white/[0.06]">
              {needsVersioning ? (
                <li className="p-4">
                  <Callout type="warning">
                    Some rules act on noncurrent versions or delete markers, but versioning is off for this bucket.
                  </Callout>
                </li>
              ) : null}
              {rules.map((rule, index) => (
                <li key={rule.id ?? index} className="flex items-start justify-between gap-4 px-4 py-3.5">
                  <div className="flex min-w-0 flex-col gap-1">
                    <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
                      <span className="truncate font-mono text-[13px] text-black dark:text-fg" title={rule.id}>
                        {rule.id}
                      </span>
                      {rule.status === 'Enabled' ? (
                        <Badge variant="success" label="Enabled" />
                      ) : (
                        <span className="text-xs text-neutral-500 dark:text-fg-faint">Disabled</span>
                      )}
                    </span>
                    <span className="text-xs text-neutral-500 dark:text-fg-faint">{summarizeFilter(rule)}</span>
                    <ul className="flex flex-col text-[13px] text-neutral-700 dark:text-fg-dim">
                      {summarizeActions(rule).map((line) => (
                        <li key={line}>{line}</li>
                      ))}
                    </ul>
                  </div>
                  <span className="flex shrink-0 items-center gap-1">
                    <button
                      type="button"
                      className="icon-button"
                      title="Edit rule"
                      aria-label={`Edit rule ${rule.id}`}
                      onClick={() => setEditing({ index })}
                    >
                      <Pencil className="size-4" />
                    </button>
                    <button
                      type="button"
                      className="icon-button hover:!text-error"
                      title="Delete rule"
                      aria-label={`Delete rule ${rule.id}`}
                      onClick={() => setDeleteIndex(index)}
                    >
                      <Trash2 className="size-4" />
                    </button>
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </section>

      {editing ? (
        <LifecycleRuleDialog
          rule={editing.index === null ? null : (rules[editing.index] ?? null)}
          versioningEnabled={versioningEnabled}
          saving={mutation.isPending}
          onClose={() => setEditing(null)}
          onSave={(rule) => void saveRule(rule)}
        />
      ) : null}

      <ConfirmDialog
        open={deleteIndex !== null}
        title="Delete lifecycle rule?"
        description={`Rule "${deleteIndex !== null ? (rules[deleteIndex]?.id ?? '') : ''}" will stop running.`}
        confirmLabel="Delete rule"
        confirmVariant="destructive"
        loading={mutation.isPending}
        onClose={() => setDeleteIndex(null)}
        onConfirm={deleteRule}
      />
    </>
  )
}
