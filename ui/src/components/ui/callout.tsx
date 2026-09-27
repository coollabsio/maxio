import type * as React from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'

const calloutVariants = cva(
  'relative flex gap-3 rounded-sm border border-neutral-200 bg-white p-3 text-sm text-black dark:border-coolgray-300 dark:bg-coolgray-100 dark:text-white',
  {
    variants: {
      type: {
        warning:
          'bg-warning-50 border-warning-300 dark:bg-warning-900/30 dark:border-warning-800 [&_.callout-title]:text-warning-800 [&_.callout-body]:text-warning-700 dark:[&_.callout-title]:text-warning-300 dark:[&_.callout-body]:text-warning-200 [&_.callout-icon]:text-warning-700 dark:[&_.callout-icon]:text-warning-300',
        danger:
          'bg-red-50 border-red-300 dark:bg-red-900/30 dark:border-red-800 [&_.callout-title]:text-red-800 [&_.callout-body]:text-red-700 dark:[&_.callout-title]:text-red-300 dark:[&_.callout-body]:text-red-200 [&_.callout-icon]:text-red-700 dark:[&_.callout-icon]:text-red-300',
        info: 'bg-blue-50 border-blue-300 dark:bg-blue-900/30 dark:border-blue-800 [&_.callout-title]:text-blue-800 [&_.callout-body]:text-blue-700 dark:[&_.callout-title]:text-blue-300 dark:[&_.callout-body]:text-blue-200 [&_.callout-icon]:text-blue-700 dark:[&_.callout-icon]:text-blue-300',
        success:
          'bg-green-50 border-green-300 dark:bg-green-900/30 dark:border-green-800 [&_.callout-title]:text-green-800 [&_.callout-body]:text-green-700 dark:[&_.callout-title]:text-green-300 dark:[&_.callout-body]:text-green-200 [&_.callout-icon]:text-green-700 dark:[&_.callout-icon]:text-green-300',
      },
    },
    defaultVariants: {
      type: 'info',
    },
  },
)

type CalloutType = NonNullable<VariantProps<typeof calloutVariants>['type']>

type CalloutProps = Omit<React.ComponentProps<'div'>, 'title'> & {
  type?: CalloutType
  title?: React.ReactNode
  icon?: React.ReactNode
}

function Callout({ className, type = 'info', title, icon, children, ...props }: CalloutProps) {
  return (
    <div data-slot="callout" className={cn(calloutVariants({ type }), className)} {...props}>
      {icon ? <div className="callout-icon shrink-0">{icon}</div> : null}
      <div className="flex-1 text-sm">
        {title ? <div className="callout-title font-bold mb-1">{title}</div> : null}
        <div className="callout-body">{children}</div>
      </div>
    </div>
  )
}

export { Callout, type CalloutProps, type CalloutType }
