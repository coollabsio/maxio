import type * as React from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'

const cardVariants = cva(
  'group bg-card text-card-foreground flex flex-col gap-6 rounded-sm border border-border py-6 shadow-sm min-h-16 transition-colors',
  {
    variants: {
      variant: {
        default: '',
        box: 'cursor-pointer hover:bg-neutral-100 dark:hover:bg-coollabs-100 dark:hover:text-white hover:text-black dark:group-hover:[&_[data-slot=card-title]]:text-white dark:group-hover:[&_[data-slot=card-description]]:text-white group-hover:[&_[data-slot=card-description]]:text-black',
        coolbox:
          'rounded cursor-pointer border-neutral-200 dark:border-coolgray-400 hover:ring-2 hover:ring-coollabs dark:hover:ring-warning',
      },
    },
    defaultVariants: {
      variant: 'default',
    },
  },
)

type CardVariant = NonNullable<VariantProps<typeof cardVariants>['variant']>
type CardProps = React.ComponentProps<'div'> & { variant?: CardVariant }

function Card({ className, variant = 'default', ...props }: CardProps) {
  return <div data-slot="card" className={cn(cardVariants({ variant }), className)} {...props} />
}

function CardHeader({ className, ...props }: React.ComponentProps<'div'>) {
  return (
    <div
      data-slot="card-header"
      className={cn(
        '@container/card-header grid auto-rows-min grid-rows-[auto_auto] items-start gap-1.5 px-6 has-data-[slot=card-action]:grid-cols-[1fr_auto] [.border-b]:pb-6',
        className,
      )}
      {...props}
    />
  )
}

function CardTitle({ className, ...props }: React.ComponentProps<'div'>) {
  return <div data-slot="card-title" className={cn('leading-none font-semibold text-black dark:text-white', className)} {...props} />
}

function CardDescription({ className, ...props }: React.ComponentProps<'p'>) {
  return <p data-slot="card-description" className={cn('text-muted-foreground text-sm', className)} {...props} />
}

function CardAction({ className, ...props }: React.ComponentProps<'div'>) {
  return (
    <div
      data-slot="card-action"
      className={cn('col-start-2 row-span-2 row-start-1 self-start justify-self-end', className)}
      {...props}
    />
  )
}

function CardContent({ className, ...props }: React.ComponentProps<'div'>) {
  return <div data-slot="card-content" className={cn('px-6', className)} {...props} />
}

function CardFooter({ className, ...props }: React.ComponentProps<'div'>) {
  return <div data-slot="card-footer" className={cn('flex items-center px-6 [.border-t]:pt-6', className)} {...props} />
}

export {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
  type CardProps,
  type CardVariant,
}
