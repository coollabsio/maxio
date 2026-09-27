import type * as React from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'

const badgeVariants = cva(
  'inline-block w-3 h-3 rounded-full leading-none border border-neutral-200 dark:border-black',
  {
    variants: {
      variant: {
        success: 'bg-success',
        warning: 'bg-warning',
        error: 'bg-error',
      },
    },
    defaultVariants: {
      variant: 'success',
    },
  },
)

type BadgeVariant = NonNullable<VariantProps<typeof badgeVariants>['variant']>

const textColors: Record<BadgeVariant, string> = {
  success: 'text-success',
  error: 'text-error',
  warning: 'text-warning',
}

type BadgeProps = React.ComponentProps<'span'> & {
  variant?: BadgeVariant
  label?: string
}

function Badge({ className, variant = 'success', label, ...props }: BadgeProps) {
  const dot = <span data-slot="badge" className={cn(badgeVariants({ variant }), className)} {...props} />
  if (!label) return dot
  return (
    <span className="inline-flex items-center gap-2">
      {dot}
      <span className={cn('text-xs font-bold', textColors[variant])}>{label}</span>
    </span>
  )
}

export { Badge, type BadgeProps, type BadgeVariant }
