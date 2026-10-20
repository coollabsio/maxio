import { Menu } from 'lucide-react'
import { Fragment, type ReactNode } from 'react'
import { useMatch, useNavigate, useSearchParams } from 'react-router'
import { bucketPath, buildBreadcrumbs, normalizePrefix } from '@/lib/paths'
import { cn } from '@/lib/utils'
import { AppVersion } from './AppVersion'
import { useAppVersion } from './useAppVersion'

const crumbClass =
  'inline-flex h-7 min-w-0 shrink-0 items-center rounded-md px-1.5 text-neutral-600 transition-colors hover:bg-black/[0.04] hover:text-black focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring dark:text-fg-dim dark:hover:bg-white/[0.06] dark:hover:text-fg'

function Separator() {
  return (
    <li className="select-none text-neutral-300 dark:text-white/20" aria-hidden="true">
      /
    </li>
  )
}

function Crumb({ onClick, children }: { onClick: () => void; children: string }) {
  return (
    <li className="min-w-0">
      <button type="button" className={crumbClass} onClick={onClick}>
        <span className="truncate">{children}</span>
      </button>
    </li>
  )
}

function Current({ children }: { children: string }) {
  return (
    <li className="min-w-0">
      <span className="block truncate px-1.5 text-black dark:text-white" aria-current="page">
        {children}
      </span>
    </li>
  )
}

/** Where the user is: Buckets / bucket / folder / … (or / Settings). Every crumb but the last navigates. */
export function Breadcrumbs({ className }: { className?: string }) {
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const settingsMatch = useMatch('/buckets/:bucket/settings')
  const objectsMatch = useMatch('/buckets/:bucket')
  const bucket = settingsMatch?.params.bucket ?? objectsMatch?.params.bucket ?? null
  const prefix = normalizePrefix(searchParams.get('prefix'))
  const crumbs = bucket ? buildBreadcrumbs(bucket, prefix) : []

  let trail: ReactNode
  if (!bucket) {
    trail = <Current>Buckets</Current>
  } else if (settingsMatch) {
    trail = (
      <>
        <Crumb onClick={() => navigate(bucketPath(bucket))}>{bucket}</Crumb>
        <Separator />
        <Current>Settings</Current>
      </>
    )
  } else {
    trail = crumbs.map((crumb, index) =>
      index < crumbs.length - 1 ? (
        <Fragment key={crumb.prefix}>
          <Crumb onClick={() => navigate(bucketPath(bucket, crumb.prefix))}>{crumb.label}</Crumb>
          <Separator />
        </Fragment>
      ) : (
        <Current key={crumb.prefix}>{crumb.label}</Current>
      ),
    )
  }

  return (
    <nav aria-label="Breadcrumb" className={cn('min-w-0 overflow-x-auto', className)}>
      <ol className="flex items-center gap-1 text-[13px] font-medium whitespace-nowrap">
        {bucket ? (
          <>
            <Crumb onClick={() => navigate('/')}>Buckets</Crumb>
            <Separator />
          </>
        ) : null}
        {trail}
      </ol>
    </nav>
  )
}

function Brand({ collapsed = false }: { collapsed?: boolean }) {
  const navigate = useNavigate()
  const version = useAppVersion()
  return (
    <button
      type="button"
      onClick={() => navigate('/')}
      title={`MaxIO v${version}`}
      className="flex min-w-0 items-center gap-2 rounded-md transition-opacity hover:opacity-80 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
    >
      <img src={`${import.meta.env.BASE_URL}logo.svg`} alt="" className="size-5 shrink-0" />
      {collapsed ? null : (
        <span className="flex min-w-0 items-baseline gap-1.5">
          <span className="text-[15px] font-semibold tracking-tight text-black dark:text-white">MaxIO</span>
          <AppVersion version={version} />
        </span>
      )}
    </button>
  )
}

/** Desktop top bar: the brand (as wide as the sidebar) and the breadcrumb. Floats as a panel in the floating style. */
export function TopBar({ collapsed }: { collapsed: boolean }) {
  return (
    <header className="app-topbar fixed inset-x-0 top-0 z-50 flex h-12 items-center bg-white/95 backdrop-blur dark:bg-panel/95">
      <div
        className={cn(
          'flex h-full shrink-0 items-center border-r border-neutral-200 transition-[width] duration-200 dark:border-white/[0.06]',
          collapsed ? 'w-16 justify-center' : 'w-56 px-4',
        )}
      >
        <Brand collapsed={collapsed} />
      </div>
      <div className="flex h-full min-w-0 flex-1 items-center border-b border-neutral-200 pr-4 pl-3 dark:border-white/[0.06]">
        <Breadcrumbs />
      </div>
    </header>
  )
}

/** Mobile top bar: the brand and the button that opens the navigation sheet. */
export function MobileTopBar({ menuOpen, onOpenMenu }: { menuOpen: boolean; onOpenMenu: () => void }) {
  return (
    <header className="sticky top-0 z-30 flex h-12 items-center justify-between gap-2 border-b border-neutral-200 bg-white/95 px-4 backdrop-blur dark:border-white/[0.06] dark:bg-panel/95">
      <Brand />
      <button
        type="button"
        onClick={onOpenMenu}
        className="-mr-1.5 flex size-8 shrink-0 items-center justify-center rounded-md text-neutral-500 transition-colors hover:bg-neutral-100 hover:text-black focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring dark:text-fg-dim dark:hover:bg-white/[0.06] dark:hover:text-fg"
        aria-label="Open menu"
        aria-expanded={menuOpen}
      >
        <Menu className="size-5" />
      </button>
    </header>
  )
}
