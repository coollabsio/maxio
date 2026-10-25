import type * as React from 'react'
import { cn } from '@/lib/utils'

function Highlighted({ className, ...props }: React.ComponentProps<'span'>) {
  return (
    <span
      data-slot="highlighted"
      className={cn('inline-block font-bold text-coollabs dark:text-brand-light', className)}
      {...props}
    />
  )
}

export { Highlighted }
