import type * as React from 'react'
import { cn } from '@/lib/utils'

function Tag({ className, ...props }: React.ComponentProps<'span'>) {
  return (
    <span
      data-slot="tag"
      className={cn(
        'inline-flex items-center px-2 py-1 text-xs font-bold rounded-sm text-neutral-500 bg-neutral-100 hover:bg-neutral-200 dark:bg-coolgray-100 dark:hover:bg-coolgray-300 cursor-pointer',
        className,
      )}
      {...props}
    />
  )
}

export { Tag }
