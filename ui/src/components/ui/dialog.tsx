import type * as React from 'react'
import { Dialog as DialogPrimitive } from '@base-ui/react/dialog'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'

type DialogProps = {
  open: boolean
  title: string
  description?: string
  loading?: boolean
  /** `lg` widens the frame (file previews); the body scrolls when taller than the viewport. */
  size?: 'default' | 'lg'
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
  size = 'default',
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
        <DialogPrimitive.Backdrop data-slot="dialog-overlay" className="fixed inset-0 z-40 cursor-default bg-black/60" />
        <DialogPrimitive.Popup
          data-slot="dialog-content"
          initialFocus={initialFocus}
          className={cn(
            'fixed left-1/2 top-1/2 z-50 max-h-[calc(100vh-2rem)] w-[calc(100vw-2rem)] -translate-x-1/2 -translate-y-1/2 overflow-y-auto rounded-sm border border-neutral-200 bg-white p-4 text-black shadow-sm outline-none dark:border-coolgray-300 dark:bg-coolgray-100 dark:text-white',
            size === 'lg' ? 'max-w-4xl' : 'max-w-lg',
          )}
        >
          <div className="flex items-start justify-between gap-4 border-b border-neutral-200 pb-3 dark:border-coolgray-200">
            <div className="flex min-w-0 flex-col gap-1">
              <DialogPrimitive.Title className="truncate text-base font-bold text-black dark:text-white">{title}</DialogPrimitive.Title>
              {description ? (
                <DialogPrimitive.Description className="truncate text-sm text-neutral-600 dark:text-neutral-400">
                  {description}
                </DialogPrimitive.Description>
              ) : null}
            </div>
            <Button variant="ghost" size="icon" className="shrink-0" aria-label={closeLabel} disabled={loading} onClick={close}>
              ×
            </Button>
          </div>

          {children}

          <div className="mt-4 flex flex-wrap justify-end gap-2 border-t border-neutral-200 pt-3 dark:border-coolgray-200">
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
