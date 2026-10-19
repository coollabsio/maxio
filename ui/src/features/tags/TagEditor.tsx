import { Plus, X } from 'lucide-react'
import { useState } from 'react'
import type { TagEntry } from '@/api/generated/types.gen'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { cleanTags, tagsEqual, validateTags } from './validation'

interface TagEditorProps {
  tags: TagEntry[]
  onChange: (tags: TagEntry[]) => void
  max: number
  disabled?: boolean
  /** Accessible name prefix of the inputs, e.g. "Object tag". */
  label?: string
}

/** Key/value rows with remove buttons and an "Add tag" button (controlled). */
export function TagEditor({ tags, onChange, max, disabled = false, label = 'Tag' }: TagEditorProps) {
  function update(index: number, patch: Partial<TagEntry>) {
    onChange(tags.map((tag, i) => (i === index ? { ...tag, ...patch } : tag)))
  }

  return (
    <div className="flex flex-col gap-2">
      {tags.length === 0 ? <p className="text-[13px] text-neutral-500 dark:text-fg-faint">No tags</p> : null}
      {tags.map((tag, index) => (
        <div key={index} className="grid grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto] items-center gap-2">
          <Input
            value={tag.key}
            placeholder="Key"
            aria-label={`${label} ${index + 1} key`}
            maxLength={128}
            disabled={disabled}
            onChange={(event) => update(index, { key: event.target.value })}
          />
          <Input
            value={tag.value}
            placeholder="Value"
            aria-label={`${label} ${index + 1} value`}
            maxLength={256}
            disabled={disabled}
            onChange={(event) => update(index, { value: event.target.value })}
          />
          <button
            type="button"
            className="icon-button hover:!text-error"
            aria-label={`Remove ${label.toLowerCase()} ${index + 1}`}
            title="Remove"
            disabled={disabled}
            onClick={() => onChange(tags.filter((_, i) => i !== index))}
          >
            <X className="size-4" />
          </button>
        </div>
      ))}
      <div>
        <Button
          variant="default"
          size="sm"
          disabled={disabled || tags.length >= max}
          onClick={() => onChange([...tags, { key: '', value: '' }])}
        >
          <Plus /> Add tag
        </Button>
      </div>
    </div>
  )
}

interface TagSetFormProps {
  /** Saved tags; remount (via `key`) to reset the draft when they change. */
  initial: TagEntry[]
  max: number
  rejectAwsPrefix?: boolean
  saving: boolean
  onSave: (tags: TagEntry[]) => void | Promise<void>
  label?: string
}

/** Tag editor with client validation and Save / Reset buttons shown once the draft differs from `initial`. */
export function TagSetForm({ initial, max, rejectAwsPrefix, saving, onSave, label }: TagSetFormProps) {
  const [draft, setDraft] = useState<TagEntry[]>(initial)
  const cleaned = cleanTags(draft)
  const error = validateTags(cleaned, max, { rejectAwsPrefix })
  const dirty = !tagsEqual(cleaned, initial)

  return (
    <form
      className="flex flex-col gap-3"
      onSubmit={(event) => {
        event.preventDefault()
        if (!error && dirty) void onSave(cleaned)
      }}
    >
      <TagEditor tags={draft} onChange={setDraft} max={max} disabled={saving} label={label} />
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-xs text-neutral-500 dark:text-fg-faint" role={error && dirty ? 'alert' : undefined}>
          {error && dirty ? <span className="text-error">{error}</span> : `${cleaned.length} / ${max} tags`}
        </span>
        {dirty ? (
          <div className="flex gap-2">
            <Button variant="default" size="sm" disabled={saving} onClick={() => setDraft(initial)}>
              Reset
            </Button>
            <Button type="submit" variant="highlighted" size="sm" disabled={saving || !!error}>
              {saving ? 'Saving…' : 'Save tags'}
            </Button>
          </div>
        ) : null}
      </div>
    </form>
  )
}
