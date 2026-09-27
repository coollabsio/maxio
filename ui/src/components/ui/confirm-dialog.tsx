import { useRef, useState } from 'react'
import { Button, type ButtonVariant } from '@/components/ui/button'
import { DialogShell } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'

type ConfirmDialogProps = {
  open: boolean
  title: string
  description?: string
  confirmLabel?: string
  cancelLabel?: string
  confirmVariant?: ButtonVariant
  /** When set, the user must type this text before the confirm button is enabled. */
  confirmationText?: string
  confirmationLabel?: string
  loading?: boolean
  onClose: () => void
  onConfirm: () => void | Promise<void>
}

function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  confirmVariant = 'highlighted',
  confirmationText,
  confirmationLabel,
  loading = false,
  onClose,
  onConfirm,
}: ConfirmDialogProps) {
  const [typedConfirmation, setTypedConfirmation] = useState('')
  const [wasOpen, setWasOpen] = useState(open)
  if (open !== wasOpen) {
    // Reset the typed text whenever the dialog closes, however it was closed.
    setWasOpen(open)
    if (!open) setTypedConfirmation('')
  }
  const confirmationInput = useRef<HTMLInputElement>(null)
  const cancelButton = useRef<HTMLButtonElement>(null)
  const canConfirm = !confirmationText || typedConfirmation === confirmationText
  const closeLabel =
    confirmVariant === 'destructive' || confirmationText ? 'Close destructive confirmation' : 'Close confirmation'

  function close() {
    if (loading) return
    onClose()
  }

  async function confirm() {
    if (!canConfirm || loading) return
    await onConfirm()
  }

  return (
    <DialogShell
      open={open}
      title={title}
      description={description}
      loading={loading}
      onClose={close}
      closeLabel={closeLabel}
      initialFocus={confirmationText ? confirmationInput : cancelButton}
      footer={
        <>
          <Button ref={cancelButton} variant="default" disabled={loading} onClick={close}>
            {cancelLabel}
          </Button>
          <Button variant={confirmVariant} disabled={loading || !canConfirm} onClick={() => void confirm()}>
            {loading ? 'Working…' : confirmLabel}
          </Button>
        </>
      }
    >
      {confirmationText ? (
        <>
          <div className="mt-4 rounded-sm border border-red-300 bg-red-50 p-3 text-sm text-red-800 dark:border-red-800 dark:bg-red-900/30 dark:text-red-300">
            Type <span className="font-mono font-bold">{confirmationText}</span> to confirm this destructive action.
          </div>
          <label className="mt-3 flex flex-col gap-1.5 text-sm font-medium text-black dark:text-white">
            {confirmationLabel ?? 'Confirmation'}
            <Input
              ref={confirmationInput}
              className="bg-white dark:bg-base"
              value={typedConfirmation}
              onChange={(event) => setTypedConfirmation(event.target.value)}
              autoComplete="off"
              disabled={loading}
            />
          </label>
        </>
      ) : null}
    </DialogShell>
  )
}

export { ConfirmDialog, type ConfirmDialogProps }
