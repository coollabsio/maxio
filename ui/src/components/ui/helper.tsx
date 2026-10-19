import { CircleHelp } from 'lucide-react'
import { cn } from '@/lib/utils'

function Helper({ text, className }: { text: string; className?: string }) {
  return (
    <span className={cn('group relative inline-flex items-center', className)}>
      <CircleHelp className="size-4 text-coollabs dark:text-warning cursor-pointer" />
      <span
        role="tooltip"
        className="hidden group-hover:block absolute left-5 top-0 z-40 max-w-sm text-xs rounded-lg border border-neutral-200 bg-white p-2 text-neutral-600 shadow-dropdown dark:border-white/10 dark:bg-coolgray-200 dark:text-fg-dim"
      >
        {text}
      </span>
    </span>
  )
}

export { Helper }
