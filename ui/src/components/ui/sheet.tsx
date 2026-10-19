import type * as React from 'react'
import { Dialog as DialogPrimitive } from '@base-ui/react/dialog'
import { X } from 'lucide-react'
import { Button } from '@/components/ui/button'

type SheetProps = {
  open: boolean
  title: string
  description?: React.ReactNode
  onClose: () => void
  closeLabel?: string
  children?: React.ReactNode
}

/**
 * Panel that slides in from the right (details drawers), built on the Base UI Dialog primitive like `Dialog`:
 * Escape, the backdrop and the × button close it. The body scrolls; the header stays in place.
 */
function Sheet({ open, title, description, onClose, closeLabel = 'Close panel', children }: SheetProps) {
  return (
    <DialogPrimitive.Root
      open={open}
      onOpenChange={(next) => {
        if (!next) onClose()
      }}
    >
      <DialogPrimitive.Portal>
        <DialogPrimitive.Backdrop
          data-slot="sheet-overlay"
          className="fixed inset-0 z-[100] cursor-default bg-black/40 transition-opacity duration-200 data-ending-style:opacity-0 data-starting-style:opacity-0"
        />
        <DialogPrimitive.Popup
          data-slot="sheet-content"
          className="fixed inset-y-0 right-0 z-[101] flex w-[min(34rem,100vw)] flex-col border-l border-neutral-200 bg-white text-black shadow-[-8px_0_30px_-6px_rgba(0,0,0,0.18)] outline-none transition-transform duration-300 ease-[cubic-bezier(0.32,0.72,0,1)] data-ending-style:translate-x-full data-starting-style:translate-x-full dark:border-white/[0.08] dark:bg-panel dark:text-fg dark:shadow-[-8px_0_30px_-4px_rgba(0,0,0,0.5)]"
        >
          <div className="flex shrink-0 items-start justify-between gap-4 border-b border-neutral-200 px-5 py-4 dark:border-white/[0.06]">
            <div className="flex min-w-0 flex-col gap-1">
              <DialogPrimitive.Title className="truncate text-base font-semibold text-black dark:text-white">
                {title}
              </DialogPrimitive.Title>
              {description ? (
                <DialogPrimitive.Description className="break-all text-[13px] text-neutral-500 dark:text-fg-faint">
                  {description}
                </DialogPrimitive.Description>
              ) : null}
            </div>
            <Button variant="ghost" size="icon-sm" className="shrink-0" aria-label={closeLabel} onClick={onClose}>
              <X />
            </Button>
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">{children}</div>
        </DialogPrimitive.Popup>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  )
}

export { Sheet }
