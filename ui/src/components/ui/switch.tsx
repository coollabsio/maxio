import { Switch as SwitchPrimitive } from '@base-ui/react/switch'
import { cn } from '@/lib/utils'

function Switch({ className, ...props }: Omit<SwitchPrimitive.Root.Props, 'className'> & { className?: string }) {
  return (
    <SwitchPrimitive.Root
      data-slot="switch"
      className={cn(
        'inline-flex h-4 w-8 shrink-0 cursor-pointer items-center rounded-full border border-transparent bg-neutral-300 p-0.5 outline-none transition-colors focus-visible:ring-2 focus-visible:ring-coollabs focus-visible:ring-offset-2 data-disabled:cursor-not-allowed data-disabled:opacity-60 data-checked:bg-coollabs dark:bg-coolgray-300 dark:focus-visible:ring-warning dark:focus-visible:ring-offset-base dark:data-checked:bg-warning',
        className,
      )}
      {...props}
    >
      <SwitchPrimitive.Thumb
        data-slot="switch-thumb"
        className="pointer-events-none block size-3 rounded-full bg-white shadow-sm transition-transform data-checked:translate-x-[14px] dark:data-checked:bg-base"
      />
    </SwitchPrimitive.Root>
  )
}

export { Switch }
