import { Button as ButtonPrimitive } from '@base-ui/react/button'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'

const depth = 'button-3d'

const buttonVariants = cva(
  "inline-flex min-w-fit shrink-0 cursor-pointer items-center justify-center gap-1.5 whitespace-nowrap rounded-md border border-transparent px-2.5 text-[13px] font-medium normal-case outline-none select-none transition-colors disabled:cursor-not-allowed disabled:border-neutral-200 disabled:bg-control disabled:bg-none disabled:text-neutral-300 dark:disabled:border-white/[0.06] dark:disabled:text-fg-faint aria-disabled:cursor-not-allowed aria-disabled:opacity-60 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring",
  {
    variants: {
      variant: {
        default: `${depth} border-neutral-200 bg-control text-black hover:bg-control-hover dark:border-white/[0.08] dark:text-fg`,
        highlighted: `${depth} button-highlighted border-coollabs-200 bg-linear-to-b from-coollabs-100 to-coollabs-200 text-white hover:to-coollabs dark:border-coollabs-200`,
        destructive: `${depth} button-error border-red-300 bg-red-50 text-red-800 hover:bg-red-100 hover:text-red-900 dark:border-red-800 dark:bg-red-900/30 dark:text-red-300 dark:hover:bg-red-700 dark:hover:text-white`,
        outline: `${depth} border-neutral-200 bg-control text-black hover:bg-control-hover dark:border-white/[0.08] dark:text-fg`,
        secondary: `${depth} border-neutral-200 bg-control-strong text-black hover:bg-control-strong-hover dark:border-white/[0.08] dark:text-fg`,
        ghost:
          'text-neutral-500 hover:bg-neutral-100 hover:text-black disabled:border-transparent disabled:bg-transparent dark:text-fg-dim dark:hover:bg-white/[0.07] dark:hover:text-fg dark:disabled:border-transparent',
        link: 'text-brand underline-offset-4 hover:underline dark:text-brand-light',
        brand: `${depth} button-highlighted border-coollabs-200 bg-linear-to-b from-coollabs-100 to-coollabs-200 text-white hover:to-coollabs`,
      },
      size: {
        default: 'h-8',
        sm: 'h-7 px-2',
        lg: 'h-10 px-3 text-sm',
        icon: 'size-8 px-0',
        'icon-sm': 'size-7 px-0',
        'icon-lg': 'size-10 px-0',
      },
    },
    defaultVariants: {
      variant: 'default',
      size: 'default',
    },
  },
)

type ButtonVariant = NonNullable<VariantProps<typeof buttonVariants>['variant']>
type ButtonSize = NonNullable<VariantProps<typeof buttonVariants>['size']>
type ButtonProps = Omit<ButtonPrimitive.Props, 'className'> & VariantProps<typeof buttonVariants> & { className?: string }

function Button({ className, variant = 'default', size = 'default', type = 'button', ...props }: ButtonProps) {
  return (
    <ButtonPrimitive
      data-slot="button"
      type={type}
      className={cn(buttonVariants({ variant, size }), className)}
      {...props}
    />
  )
}

export { Button, type ButtonProps, type ButtonSize, type ButtonVariant }
