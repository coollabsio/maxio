import { Database, ScrollText, Users, X } from 'lucide-react'
import { useLocation, useNavigate } from 'react-router'
import { cn } from '@/lib/utils'
import { DESKTOP_QUERY, useMediaQuery } from '@/lib/useMediaQuery'
import { UserMenu } from './UserMenu'

interface SidebarProps {
  collapsed: boolean
  /** Below the `lg` breakpoint the sidebar is a sheet; this opens it. */
  mobileOpen: boolean
  onCloseMobile: () => void
  onToggleCollapsed: () => void
  onHome: () => void
  onLogout: () => void
  iamAdmin: boolean
  accountName: string
  accountDetail: string
}

function SidebarToggleIcon() {
  return (
    <svg className="menu-item-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <rect x="3" y="5" width="18" height="14" rx="4" stroke="currentColor" strokeWidth="1.6" />
      <path d="M16 9v6" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
    </svg>
  )
}

export function Sidebar({
  collapsed: collapsedSetting,
  mobileOpen,
  onCloseMobile,
  onToggleCollapsed,
  onHome,
  onLogout,
  iamAdmin,
  accountName,
  accountDetail,
}: SidebarProps) {
  const isDesktop = useMediaQuery(DESKTOP_QUERY)
  const navigate = useNavigate()
  const { pathname } = useLocation()
  // The mobile sheet is always shown expanded.
  const collapsed = collapsedSetting && isDesktop
  const bucketsActive = pathname === '/' || pathname.startsWith('/buckets')
  const usersActive = pathname === '/users' || pathname.startsWith('/users/')
  const policiesActive = pathname === '/policies' || pathname.startsWith('/policies/')

  function go(path: string) {
    onCloseMobile()
    navigate(path)
  }

  const nav = (
    <nav
      aria-label="Main"
      inert={!isDesktop && !mobileOpen}
      className={cn(
        'app-sidebar-panel flex min-h-0 flex-1 flex-col bg-white px-2 pt-2 dark:bg-panel lg:px-3',
        isDesktop && 'border-r border-neutral-200 dark:border-white/[0.06]',
        collapsed && 'sidebar-collapsed',
      )}
    >
      <ul className="flex flex-col gap-0.5 overflow-y-auto">
        {collapsed ? null : <li className="nav-section">Storage</li>}
        <li>
          <button
            type="button"
            onClick={onHome}
            title="Buckets"
            aria-current={bucketsActive ? 'page' : undefined}
            className={cn('menu-item', bucketsActive && 'menu-item-active', collapsed && 'justify-center px-0')}
          >
            <Database className="menu-item-icon" aria-hidden="true" />
            {collapsed ? null : <span className="menu-item-label">Buckets</span>}
          </button>
        </li>
        {iamAdmin ? (
          <>
            {collapsed ? null : <li className="nav-section">Access</li>}
            <li>
              <button
                type="button"
                onClick={() => go('/users')}
                title="Users"
                aria-current={usersActive ? 'page' : undefined}
                className={cn('menu-item', usersActive && 'menu-item-active', collapsed && 'justify-center px-0')}
              >
                <Users className="menu-item-icon" aria-hidden="true" />
                {collapsed ? null : <span className="menu-item-label">Users</span>}
              </button>
            </li>
            <li>
              <button
                type="button"
                onClick={() => go('/policies')}
                title="Policies"
                aria-current={policiesActive ? 'page' : undefined}
                className={cn('menu-item', policiesActive && 'menu-item-active', collapsed && 'justify-center px-0')}
              >
                <ScrollText className="menu-item-icon" aria-hidden="true" />
                {collapsed ? null : <span className="menu-item-label">Policies</span>}
              </button>
            </li>
          </>
        ) : null}
      </ul>

      <div className="app-sidebar-footer sticky bottom-0 mt-auto -mx-2 flex flex-col gap-1 bg-white px-2 py-2 dark:bg-panel lg:-mx-3 lg:px-3">
        <div className={cn('flex items-center gap-1', collapsed ? 'flex-col justify-center' : 'justify-between')}>
          <UserMenu collapsed={collapsed} onLogout={onLogout} name={accountName} detail={accountDetail} />
          {isDesktop ? (
            <button
              type="button"
              onClick={onToggleCollapsed}
              title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
              aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
              aria-expanded={!collapsed}
              className="menu-item sidebar-toggle w-8 shrink-0 justify-center px-0"
            >
              <SidebarToggleIcon />
            </button>
          ) : null}
        </div>
      </div>
    </nav>
  )

  if (isDesktop) {
    return (
      <div
        className={cn(
          'app-sidebar fixed top-12 bottom-0 left-0 z-40 flex min-w-0 flex-col transition-[width] duration-200',
          collapsed ? 'w-16' : 'w-56',
        )}
      >
        {nav}
      </div>
    )
  }

  // Mobile: a sheet that slides in from the right, like Coolify.
  return (
    <div
      className={cn(
        'fixed inset-y-0 right-0 z-40 flex w-72 max-w-[85vw] flex-col overflow-hidden rounded-l-2xl border-l border-neutral-200 bg-white shadow-[-8px_0_30px_-6px_rgba(0,0,0,0.18)] transition-transform duration-300 ease-[cubic-bezier(0.32,0.72,0,1)] dark:border-white/[0.12] dark:bg-panel dark:shadow-[-8px_0_30px_-4px_rgba(0,0,0,0.5)]',
        mobileOpen ? 'translate-x-0' : 'pointer-events-none translate-x-full',
      )}
    >
      <div className="flex h-12 shrink-0 items-center justify-between border-b border-neutral-200 px-4 dark:border-white/[0.06]">
        <span className="text-[15px] font-semibold tracking-tight text-black dark:text-white">MaxIO</span>
        <button
          type="button"
          onClick={onCloseMobile}
          tabIndex={mobileOpen ? 0 : -1}
          aria-label="Close navigation"
          className="-mr-1.5 flex size-8 items-center justify-center rounded-md text-neutral-500 transition-colors hover:bg-neutral-100 hover:text-black dark:text-fg-dim dark:hover:bg-white/[0.06] dark:hover:text-fg"
        >
          <X className="size-5" />
        </button>
      </div>
      {nav}
    </div>
  )
}
