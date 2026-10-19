import type * as React from 'react'
import { cn } from '@/lib/utils'

function Kbd({ className, ...props }: React.ComponentProps<'kbd'>) {
  return (
    <kbd
      data-slot="kbd"
      className={cn('inline-block rounded-md border border-neutral-200 bg-white px-1.5 font-mono text-[11px] text-neutral-500 dark:border-white/[0.1] dark:bg-white/[0.04] dark:text-fg-faint', className)}
      {...props}
    />
  )
}

export { Kbd }
