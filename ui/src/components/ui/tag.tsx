import type * as React from 'react'
import { cn } from '@/lib/utils'

function Tag({ className, ...props }: React.ComponentProps<'span'>) {
  return (
    <span
      data-slot="tag"
      className={cn(
        'inline-flex items-center px-2 py-1 text-xs font-medium rounded-md text-neutral-500 bg-neutral-100 hover:bg-neutral-200 dark:text-fg-faint dark:bg-white/[0.06] dark:hover:bg-white/[0.1] cursor-pointer',
        className,
      )}
      {...props}
    />
  )
}

export { Tag }
