import { useState, type ReactNode } from 'react'
import type { LifecycleRule } from '@/api/generated/types.gen'
import { Button } from '@/components/ui/button'
import { Dialog } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { TagEditor } from '@/features/tags/TagEditor'
import { emptyRuleForm, formToRule, ruleToForm, type ExpirationMode, type LifecycleRuleForm } from './rules'

interface LifecycleRuleDialogProps {
  /** Rule being edited, or `null` to add a new one. */
  rule: LifecycleRule | null
  versioningEnabled: boolean
  saving: boolean
  onClose: () => void
  onSave: (rule: LifecycleRule) => void
}

const expirationOptions: { value: ExpirationMode; label: string }[] = [
  { value: 'none', label: 'Do not expire current versions' },
  { value: 'days', label: 'After a number of days' },
  { value: 'date', label: 'On a date' },
  { value: 'deleteMarkers', label: 'Remove expired delete markers' },
]

/** Add / edit form for one lifecycle rule. Mount it only while open so the form starts from `rule`. */
export function LifecycleRuleDialog({ rule, versioningEnabled, saving, onClose, onSave }: LifecycleRuleDialogProps) {
  const [form, setForm] = useState<LifecycleRuleForm>(() => (rule ? ruleToForm(rule) : emptyRuleForm()))
  const [submitted, setSubmitted] = useState(false)
  const result = formToRule(form)
  const set = (patch: Partial<LifecycleRuleForm>) => setForm((current) => ({ ...current, ...patch }))

  return (
    <Dialog
      open
      title={rule ? 'Edit lifecycle rule' : 'Add lifecycle rule'}
      description="Rules run in the background and permanently delete matching data."
      loading={saving}
      onClose={onClose}
      footer={
        <>
          <Button variant="default" disabled={saving} onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" form="lifecycle-rule-form" variant="highlighted" disabled={saving}>
            {saving ? 'Saving…' : 'Save rule'}
          </Button>
        </>
      }
    >
      <form
        id="lifecycle-rule-form"
        className="-mx-1 flex max-h-[60vh] flex-col gap-5 overflow-y-auto px-1"
        onSubmit={(event) => {
          event.preventDefault()
          setSubmitted(true)
          if (result.rule) onSave(result.rule)
        }}
      >
        <div className="grid grid-cols-[minmax(0,1fr)_auto] items-end gap-4">
          <Field label="Rule ID" htmlFor="lc-id" hint="Optional. Generated when empty.">
            <Input id="lc-id" value={form.id} maxLength={255} onChange={(e) => set({ id: e.target.value })} />
          </Field>
          <label className="flex h-8 items-center gap-2 text-[13px] font-medium text-black dark:text-fg">
            <Switch checked={form.enabled} onCheckedChange={(enabled) => set({ enabled })} aria-label="Rule enabled" />
            Enabled
          </label>
        </div>

        <Group title="Filter" description="Empty filter = every object in the bucket.">
          <Field label="Prefix" htmlFor="lc-prefix">
            <Input
              id="lc-prefix"
              value={form.prefix}
              placeholder="logs/"
              onChange={(e) => set({ prefix: e.target.value })}
            />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Larger than (bytes)" htmlFor="lc-gt">
              <Input
                id="lc-gt"
                inputMode="numeric"
                value={form.sizeGreaterThan}
                onChange={(e) => set({ sizeGreaterThan: e.target.value })}
              />
            </Field>
            <Field label="Smaller than (bytes)" htmlFor="lc-lt">
              <Input
                id="lc-lt"
                inputMode="numeric"
                value={form.sizeLessThan}
                onChange={(e) => set({ sizeLessThan: e.target.value })}
              />
            </Field>
          </div>
          <div className="flex flex-col gap-1.5">
            <span className="text-[13px] font-medium text-black dark:text-fg">Object tags</span>
            <TagEditor tags={form.tags} onChange={(tags) => set({ tags })} max={10} label="Filter tag" />
          </div>
        </Group>

        <Group title="Current versions">
          <Field label="Expiration" htmlFor="lc-exp">
            <select
              id="lc-exp"
              className="input-cool"
              value={form.expirationMode}
              onChange={(e) => set({ expirationMode: e.target.value as ExpirationMode })}
            >
              {expirationOptions.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </Field>
          {form.expirationMode === 'days' ? (
            <Field label="Days after creation" htmlFor="lc-exp-days">
              <Input
                id="lc-exp-days"
                inputMode="numeric"
                value={form.expirationDays}
                onChange={(e) => set({ expirationDays: e.target.value })}
              />
            </Field>
          ) : null}
          {form.expirationMode === 'date' ? (
            <Field label="Date (midnight UTC)" htmlFor="lc-exp-date">
              <Input
                id="lc-exp-date"
                type="date"
                value={form.expirationDate}
                onChange={(e) => set({ expirationDate: e.target.value })}
              />
            </Field>
          ) : null}
          {form.expirationMode === 'deleteMarkers' && !versioningEnabled ? <VersioningHint /> : null}
        </Group>

        <Group title="Noncurrent versions">
          <div className="grid grid-cols-2 gap-3">
            <Field label="Delete after (days)" htmlFor="lc-nc-days">
              <Input
                id="lc-nc-days"
                inputMode="numeric"
                value={form.noncurrentDays}
                onChange={(e) => set({ noncurrentDays: e.target.value })}
              />
            </Field>
            <Field label="Keep newest" htmlFor="lc-nc-keep" hint="1–100 versions">
              <Input
                id="lc-nc-keep"
                inputMode="numeric"
                value={form.keepNewest}
                onChange={(e) => set({ keepNewest: e.target.value })}
              />
            </Field>
          </div>
          {!versioningEnabled ? <VersioningHint /> : null}
        </Group>

        <Group title="Incomplete multipart uploads">
          <Field label="Abort after (days)" htmlFor="lc-abort">
            <Input
              id="lc-abort"
              inputMode="numeric"
              value={form.abortDays}
              onChange={(e) => set({ abortDays: e.target.value })}
            />
          </Field>
        </Group>

        {submitted && result.error ? (
          <p role="alert" className="text-[13px] text-error">
            {result.error}
          </p>
        ) : null}
      </form>
    </Dialog>
  )
}

function VersioningHint() {
  return (
    <p className="text-xs text-warning-700 dark:text-warning">
      Versioning is off for this bucket, so there are no noncurrent versions or delete markers to clean up.
    </p>
  )
}

function Group({ title, description, children }: { title: string; description?: string; children: ReactNode }) {
  return (
    <fieldset className="flex flex-col gap-3 border-t border-neutral-200 pt-4 dark:border-white/[0.06]">
      <legend className="sr-only">{title}</legend>
      <div className="flex flex-col gap-0.5">
        <span className="text-[13px] font-semibold text-black dark:text-white">{title}</span>
        {description ? <span className="text-xs text-neutral-500 dark:text-fg-faint">{description}</span> : null}
      </div>
      {children}
    </fieldset>
  )
}

function Field({ label, htmlFor, hint, children }: { label: string; htmlFor: string; hint?: string; children: ReactNode }) {
  return (
    <div className="flex min-w-0 flex-col gap-1.5">
      <label htmlFor={htmlFor} className="text-[13px] font-medium text-black dark:text-fg">
        {label}
      </label>
      {children}
      {hint ? <span className="text-xs text-neutral-500 dark:text-fg-faint">{hint}</span> : null}
    </div>
  )
}
