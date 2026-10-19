import type * as React from 'react'
import { Dialog as DialogPrimitive } from '@base-ui/react/dialog'
import { X } from 'lucide-react'
import { Button } from '@/components/ui/button'

type DialogProps = {
  open: boolean
  title: string
  description?: string
  loading?: boolean
  onClose: () => void
  /** Element focused when the dialog opens (defaults to the first focusable element). */
  initialFocus?: React.RefObject<HTMLElement | null>
  /** Accessible label of the × button in the header. */
  closeLabel?: string
  children?: React.ReactNode
  footer?: React.ReactNode
}

/**
 * Coolify-styled modal frame built on the Base UI Dialog primitive: header with title, description and a close
 * button, free-form content, and a footer row. Escape, the backdrop, and the × button close it unless `loading`.
 */
function DialogShell({
  open,
  title,
  description,
  loading = false,
  onClose,
  initialFocus,
  closeLabel = 'Close dialog',
  children,
  footer,
}: DialogProps) {
  function close() {
    if (loading) return
    onClose()
  }

  return (
    <DialogPrimitive.Root
      open={open}
      onOpenChange={(next) => {
        if (!next) close()
      }}
    >
      <DialogPrimitive.Portal>
        <DialogPrimitive.Backdrop data-slot="dialog-overlay" className="fixed inset-0 z-[100] cursor-default bg-black/60 transition-opacity duration-150 data-ending-style:opacity-0 data-starting-style:opacity-0" />
        <DialogPrimitive.Popup
          data-slot="dialog-content"
          initialFocus={initialFocus}
          className="fixed left-1/2 top-1/2 z-[101] w-[calc(100vw-2rem)] max-w-lg -translate-x-1/2 -translate-y-1/2 rounded-xl border border-neutral-200 bg-white p-5 text-black shadow-modal outline-none transition-[opacity,scale] duration-150 data-ending-style:scale-95 data-ending-style:opacity-0 data-starting-style:scale-95 data-starting-style:opacity-0 dark:border-white/[0.08] dark:bg-panel dark:text-fg"
        >
          <div className="flex items-start justify-between gap-4 pb-1">
            <div className="flex min-w-0 flex-col gap-1">
              <DialogPrimitive.Title className="text-base font-semibold text-black dark:text-white">{title}</DialogPrimitive.Title>
              {description ? (
                <DialogPrimitive.Description className="text-[13px] text-neutral-500 dark:text-fg-faint">
                  {description}
                </DialogPrimitive.Description>
              ) : null}
            </div>
            <Button variant="ghost" size="icon-sm" className="shrink-0" aria-label={closeLabel} disabled={loading} onClick={close}>
              <X />
            </Button>
          </div>

          {children}

          <div className="mt-5 flex flex-wrap justify-end gap-2">
            {footer ?? (
              <Button variant="default" disabled={loading} onClick={close}>
                Close
              </Button>
            )}
          </div>
        </DialogPrimitive.Popup>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  )
}

/** Dialog with the standard body area (form content, messages). */
function Dialog({ children, ...props }: DialogProps) {
  return (
    <DialogShell {...props}>
      <div className="mt-4 text-sm text-neutral-700 dark:text-neutral-300">{children}</div>
    </DialogShell>
  )
}

export { Dialog, DialogShell, type DialogProps }
