import type * as React from 'react'

/** Page title row (Coolify v4.5): title and description on the left, the page actions on the right. */
function PageHeader({
  title,
  description,
  actions,
}: {
  title: string
  description?: React.ReactNode
  actions?: React.ReactNode
}) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-x-6 gap-y-3">
      <div className="flex min-w-0 flex-col gap-1">
        <h1 className="truncate">{title}</h1>
        {description ? <p className="text-[13px] text-neutral-500 dark:text-fg-faint">{description}</p> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  )
}

export { PageHeader }
