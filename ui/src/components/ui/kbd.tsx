import type * as React from 'react'
import { cn } from '@/lib/utils'

function Kbd({ className, ...props }: React.ComponentProps<'kbd'>) {
  return (
    <kbd
      data-slot="kbd"
      className={cn('inline-block px-2 text-xs rounded-sm border border-dashed border-neutral-700 dark:text-warning', className)}
      {...props}
    />
  )
}

export { Kbd }
