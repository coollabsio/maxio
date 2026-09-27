import { CircleHelp } from 'lucide-react'
import { cn } from '@/lib/utils'

function Helper({ text, className }: { text: string; className?: string }) {
  return (
    <span className={cn('group relative inline-flex items-center', className)}>
      <CircleHelp className="size-4 text-coollabs dark:text-warning cursor-pointer" />
      <span
        role="tooltip"
        className="hidden group-hover:block absolute left-5 top-0 z-40 max-w-sm text-xs bg-neutral-200 dark:bg-coolgray-400 text-neutral-700 dark:text-neutral-300 rounded-sm p-2 shadow-md"
      >
        {text}
      </span>
    </span>
  )
}

export { Helper }
