import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { Outlet, useNavigate } from 'react-router'
import { Toaster } from '@/components/ui/sonner'
import { logout } from '@/features/auth/api'
import { useTheme } from '@/lib/theme'
import { Header } from './Header'
import { Sidebar } from './Sidebar'
import { readSidebarCollapsed, storeSidebarCollapsed } from './sidebarState'

export function AppShell() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { isDark } = useTheme()
  const [collapsed, setCollapsed] = useState(readSidebarCollapsed)
  const [menuOpen, setMenuOpen] = useState(false)

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
    const next = !collapsed
    setCollapsed(next)
    storeSidebarCollapsed(next)
  }

  return (
    <>
      <div className="relative flex h-screen bg-background">
        {menuOpen ? (
          <button
            type="button"
            className="fixed inset-0 z-30 bg-black/50 md:hidden"
            aria-label="Close menu"
            onClick={() => setMenuOpen(false)}
          />
        ) : null}
        <Sidebar
          collapsed={collapsed}
          mobileOpen={menuOpen}
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
        <main className="flex min-w-0 flex-1 flex-col overflow-hidden">
          <Header menuOpen={menuOpen} onOpenMenu={() => setMenuOpen(true)} />
          <div className="flex-1 overflow-auto p-4 md:p-6">
            <Outlet />
          </div>
        </main>
      </div>
      <Toaster theme={isDark ? 'dark' : 'light'} />
    </>
  )
}
