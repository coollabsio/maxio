import { Button as ButtonPrimitive } from '@base-ui/react/button'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'

const buttonVariants = cva(
  "inline-flex min-w-fit shrink-0 cursor-pointer items-center justify-center gap-2 whitespace-nowrap rounded-sm border-2 border-transparent bg-clip-padding px-2 text-sm font-medium normal-case outline-none transition-colors select-none disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-100 disabled:border-neutral-300 disabled:bg-neutral-100 disabled:text-neutral-600 dark:disabled:border-coolgray-300 dark:disabled:bg-coolgray-100/60 dark:disabled:text-neutral-400 aria-disabled:pointer-events-none aria-disabled:opacity-100 aria-disabled:border-neutral-300 aria-disabled:bg-neutral-100 aria-disabled:text-neutral-600 dark:aria-disabled:border-coolgray-300 dark:aria-disabled:bg-coolgray-100/60 dark:aria-disabled:text-neutral-400 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-coollabs dark:focus-visible:ring-warning focus-visible:ring-offset-2 focus-visible:ring-offset-background dark:focus-visible:ring-offset-base",
  {
    variants: {
      variant: {
        default:
          'bg-white text-black border-neutral-200 hover:bg-neutral-100 dark:bg-coolgray-100 dark:text-white dark:border-coolgray-300 dark:hover:bg-coolgray-200',
        highlighted:
          'text-coollabs-200 bg-coollabs-50 border-coollabs hover:bg-coollabs hover:text-white dark:text-white dark:bg-coollabs/20 dark:border-coollabs-100 dark:hover:bg-coollabs-100 dark:hover:text-white',
        destructive:
          'text-red-800 bg-red-50 border-red-300 hover:bg-error hover:text-white dark:text-red-300 dark:bg-red-900/30 dark:border-red-800 dark:hover:bg-red-800 dark:hover:text-white',
        outline:
          'bg-transparent text-black border-neutral-200 hover:bg-neutral-100 dark:text-white dark:border-coolgray-300 dark:hover:bg-coolgray-200',
        secondary:
          'bg-neutral-100 text-black border-neutral-200 hover:bg-neutral-200 dark:bg-coolgray-200 dark:text-white dark:border-coolgray-300 dark:hover:bg-coolgray-300',
        ghost: 'border-transparent text-black hover:bg-neutral-100 dark:text-white dark:hover:bg-coolgray-200',
        link: 'border-transparent text-coollabs dark:text-warning underline-offset-4 hover:underline',
        brand: 'bg-brand text-brand-foreground border-brand hover:bg-brand-hover hover:border-brand-hover',
      },
      size: {
        default: 'h-8 has-[>svg]:px-2',
        sm: 'h-8 px-2 text-sm has-[>svg]:px-2',
        lg: 'h-10 px-3 has-[>svg]:px-3',
        icon: 'size-8',
        'icon-sm': 'size-8',
        'icon-lg': 'size-10',
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
