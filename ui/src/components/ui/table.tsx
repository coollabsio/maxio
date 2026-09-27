import type * as React from 'react'
import { cn } from '@/lib/utils'

function Table({ className, ...props }: React.ComponentProps<'table'>) {
  return (
    <div
      data-slot="table-container"
      className="relative w-full overflow-x-auto rounded-sm border border-neutral-200 dark:border-coolgray-300"
    >
      <table
        data-slot="table"
        className={cn('w-full min-w-[42rem] border-collapse caption-bottom text-left text-sm', className)}
        {...props}
      />
    </div>
  )
}

function TableHeader({ className, ...props }: React.ComponentProps<'thead'>) {
  return (
    <thead
      data-slot="table-header"
      className={cn('border-b border-neutral-200 bg-neutral-100 dark:border-coolgray-300 dark:bg-coolgray-200', className)}
      {...props}
    />
  )
}

function TableBody({ className, ...props }: React.ComponentProps<'tbody'>) {
  return <tbody data-slot="table-body" className={cn('[&_tr:last-child]:border-0', className)} {...props} />
}

function TableFooter({ className, ...props }: React.ComponentProps<'tfoot'>) {
  return (
    <tfoot
      data-slot="table-footer"
      className={cn('bg-muted/50 border-t font-medium [&>tr]:last:border-b-0', className)}
      {...props}
    />
  )
}

function TableRow({ className, ...props }: React.ComponentProps<'tr'>) {
  return (
    <tr
      data-slot="table-row"
      className={cn(
        'border-b border-neutral-200 dark:border-coolgray-200 transition-colors hover:bg-neutral-100 dark:hover:bg-coolgray-200 data-[state=selected]:bg-neutral-100 dark:data-[state=selected]:bg-coolgray-200',
        className,
      )}
      {...props}
    />
  )
}

function TableHead({ className, ...props }: React.ComponentProps<'th'>) {
  return (
    <th
      data-slot="table-head"
      className={cn(
        'bg-clip-padding px-3 py-2 text-start align-middle text-xs font-bold uppercase tracking-wide text-neutral-600 whitespace-nowrap dark:text-neutral-400 [&:has([role=checkbox])]:pe-0',
        className,
      )}
      {...props}
    />
  )
}

function TableCell({ className, ...props }: React.ComponentProps<'td'>) {
  return (
    <td
      data-slot="table-cell"
      className={cn('bg-clip-padding px-3 py-2 align-middle whitespace-nowrap [&:has([role=checkbox])]:pe-0', className)}
      {...props}
    />
  )
}

function TableCaption({ className, ...props }: React.ComponentProps<'caption'>) {
  return <caption data-slot="table-caption" className={cn('text-muted-foreground mt-4 text-sm', className)} {...props} />
}

export { Table, TableBody, TableCaption, TableCell, TableFooter, TableHead, TableHeader, TableRow }
