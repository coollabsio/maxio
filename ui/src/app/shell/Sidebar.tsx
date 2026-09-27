import { Home, LogOut, Monitor, Moon, Sun, type LucideIcon } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useTheme, type ThemeMode } from '@/lib/theme'
import { DESKTOP_QUERY, useMediaQuery } from '@/lib/useMediaQuery'

const themeOptions: { mode: ThemeMode; label: string; icon: LucideIcon }[] = [
  { mode: 'light', label: 'Light', icon: Sun },
  { mode: 'system', label: 'System', icon: Monitor },
  { mode: 'dark', label: 'Dark', icon: Moon },
]

interface SidebarProps {
  collapsed: boolean
  /** Below the `md` breakpoint the sidebar is a drawer; this opens it. */
  mobileOpen: boolean
  onToggleCollapsed: () => void
  onHome: () => void
  onLogout: () => void
}

export function Sidebar({ collapsed: collapsedSetting, mobileOpen, onToggleCollapsed, onHome, onLogout }: SidebarProps) {
  const isDesktop = useMediaQuery(DESKTOP_QUERY)
  // The mobile drawer is always shown expanded.
  const collapsed = collapsedSetting && isDesktop
  const { mode: themeMode, setTheme } = useTheme()
  const currentTheme = themeOptions.find((option) => option.mode === themeMode) ?? themeOptions[1]

  function cycleTheme() {
    const index = themeOptions.findIndex((option) => option.mode === themeMode)
    setTheme(themeOptions[(index + 1) % themeOptions.length]?.mode ?? 'system')
  }

  const CurrentThemeIcon = currentTheme.icon

  return (
    <nav
      aria-label="Main"
      inert={!isDesktop && !mobileOpen}
      className={cn(
        'fixed inset-y-0 left-0 z-40 flex w-64 flex-col border-r bg-sidebar-background transition-transform duration-200 md:relative md:translate-x-0 md:transition-[width]',
        mobileOpen ? 'translate-x-0' : '-translate-x-full',
        collapsed && 'md:w-16',
      )}
      style={{ borderColor: 'var(--cool-sidebar-border)' }}
    >
      {/* Collapse/expand toggle */}
      <button
        type="button"
        onClick={onToggleCollapsed}
        className="absolute top-8 -right-3 z-10 hidden size-6 md:flex items-center justify-center rounded-full border bg-card text-muted-foreground shadow-sm transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-coollabs dark:focus-visible:ring-warning focus-visible:ring-offset-2 dark:focus-visible:ring-offset-base"
        style={{ borderColor: 'var(--cool-sidebar-border)' }}
        title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        aria-expanded={!collapsed}
      >
        <svg
          className={cn('size-3.5 transition-transform', collapsed && 'rotate-180')}
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2.2"
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden="true"
        >
          <path d="M15 18 9 12l6-6" />
        </svg>
      </button>

      {/* Logo */}
      <div className={cn('flex h-14 items-center overflow-hidden', collapsed ? 'justify-center' : 'px-4')}>
        <img src={`${import.meta.env.BASE_URL}logo.svg`} alt="MaxIO" className="size-[26px] shrink-0" />
        {!collapsed ? (
          <span className="ml-2 text-2xl font-bold tracking-tight text-foreground whitespace-nowrap">MaxIO</span>
        ) : null}
      </div>

      {/* Nav items */}
      <div className="flex flex-1 flex-col gap-0.5 p-2">
        <button
          type="button"
          onClick={onHome}
          className={cn(
            'flex min-h-7 w-full items-center rounded-sm py-1 text-left text-sm font-medium transition-colors overflow-hidden bg-neutral-200 text-black dark:bg-coolgray-200 dark:text-warning hover:bg-neutral-300 dark:hover:bg-coolgray-100',
            collapsed ? 'justify-center size-8' : 'gap-3 px-2',
          )}
          title="Buckets"
        >
          <Home className="size-4 shrink-0" />
          {!collapsed ? <span className="whitespace-nowrap">Buckets</span> : null}
        </button>
      </div>

      {/* Bottom: theme toggle + logout */}
      <div className="flex flex-col gap-0.5 p-2">
        {collapsed ? (
          <button
            type="button"
            onClick={cycleTheme}
            className="mx-auto flex size-8 items-center justify-center rounded-sm text-sm font-medium text-muted-foreground transition-colors hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-coollabs dark:focus-visible:ring-warning"
            aria-label={`Theme: ${currentTheme.label}. Click to switch theme.`}
            title={`Theme: ${currentTheme.label}`}
          >
            <CurrentThemeIcon className="size-4 shrink-0" />
          </button>
        ) : (
          <div className="flex min-h-7 w-full items-center justify-between gap-3 rounded-sm px-2 py-1 text-sm text-muted-foreground">
            <span className="whitespace-nowrap">Theme</span>
            <div className="inline-flex items-center gap-0.5 rounded-sm bg-neutral-100 p-0.5 dark:bg-coolgray-200" aria-label="Theme">
              {themeOptions.map((option) => {
                const Icon = option.icon
                const active = themeMode === option.mode
                return (
                  <button
                    key={option.mode}
                    type="button"
                    onClick={() => setTheme(option.mode)}
                    className={cn(
                      'grid size-6 place-items-center rounded-sm text-neutral-500 transition-colors hover:text-black focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-coollabs dark:text-neutral-400 dark:hover:text-white dark:focus-visible:ring-warning',
                      active && 'bg-white text-coollabs shadow-sm dark:bg-base dark:text-warning',
                    )}
                    aria-label={`Use ${option.label} theme`}
                    aria-pressed={active}
                    title={option.label}
                  >
                    <Icon className="size-4" />
                  </button>
                )
              })}
            </div>
          </div>
        )}
        <button
          type="button"
          onClick={onLogout}
          className={cn(
            'flex min-h-7 w-full items-center rounded-sm py-1 text-left text-sm font-medium text-muted-foreground transition-colors hover:bg-muted overflow-hidden',
            collapsed ? 'justify-center size-8' : 'gap-3 px-2',
          )}
          aria-label="Sign out"
          title="Sign out"
        >
          <LogOut className="size-4 shrink-0" />
          {!collapsed ? <span className="whitespace-nowrap">Sign out</span> : null}
        </button>
      </div>
    </nav>
  )
}
