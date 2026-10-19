import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState, type CSSProperties } from 'react'
import { Outlet, useNavigate } from 'react-router'
import { Toaster } from '@/components/ui/sonner'
import { logout } from '@/features/auth/api'
import { useTheme } from '@/lib/theme'
import { DESKTOP_QUERY, useMediaQuery } from '@/lib/useMediaQuery'
import { cn } from '@/lib/utils'
import { Breadcrumbs, MobileTopBar, TopBar } from './Header'
import { Sidebar } from './Sidebar'
import { readSidebarCollapsed, storeSidebarCollapsed } from './sidebarState'

/**
 * Coolify v4.5 layout: a fixed top bar (brand + breadcrumb), a fixed sidebar below it, and the page in a centered
 * column. With the floating navigation style (index.css) the bars become framed panels over a dotted backdrop.
 */
export function AppShell() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { isDark } = useTheme()
  const isDesktop = useMediaQuery(DESKTOP_QUERY)
  const [collapsedSetting, setCollapsed] = useState(readSidebarCollapsed)
  const [menuOpen, setMenuOpen] = useState(false)
  const collapsed = collapsedSetting && isDesktop

  useEffect(() => {
    if (!menuOpen) return
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setMenuOpen(false)
    }
    window.addEventListener('keydown', closeOnEscape)
    return () => window.removeEventListener('keydown', closeOnEscape)
  }, [menuOpen])

  const logoutMutation = useMutation({
    mutationFn: logout,
    onSettled: () => {
      queryClient.clear()
      navigate('/login', { replace: true })
    },
  })

  function toggleCollapsed() {
    const next = !collapsedSetting
    setCollapsed(next)
    storeSidebarCollapsed(next)
  }

  return (
    <>
      <div
        className="app-shell min-h-dvh bg-app"
        style={{ '--sidebar-w': collapsed ? '4rem' : '14rem' } as CSSProperties}
      >
        {isDesktop ? (
          <TopBar collapsed={collapsed} />
        ) : (
          <MobileTopBar menuOpen={menuOpen} onOpenMenu={() => setMenuOpen(true)} />
        )}
        {menuOpen && !isDesktop ? (
          <button
            type="button"
            className="fixed inset-0 z-30 animate-in bg-black/50 fade-in-0"
            aria-label="Close menu"
            onClick={() => setMenuOpen(false)}
          />
        ) : null}
        <Sidebar
          collapsed={collapsedSetting}
          mobileOpen={menuOpen}
          onCloseMobile={() => setMenuOpen(false)}
          onToggleCollapsed={toggleCollapsed}
          onHome={() => {
            setMenuOpen(false)
            navigate('/')
          }}
          onLogout={() => {
            setMenuOpen(false)
            logoutMutation.mutate()
          }}
        />
        <main
          className={cn(
            'app-main min-h-dvh bg-app px-5 py-6 transition-[margin] duration-200 sm:px-8 lg:px-10 lg:pt-[calc(3rem+1.75rem)] lg:pb-10',
            collapsed ? 'lg:ml-16' : 'lg:ml-56',
          )}
        >
          <div className="mx-auto w-full max-w-[1400px]">
            {isDesktop ? null : <Breadcrumbs className="-mx-1.5 mb-4" />}
            <Outlet />
          </div>
        </main>
      </div>
      <Toaster theme={isDark ? 'dark' : 'light'} />
    </>
  )
}
