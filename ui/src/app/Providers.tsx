import { QueryClientProvider, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState, type ReactNode } from 'react'
import { BrowserRouter, useNavigate } from 'react-router'
import { UNAUTHORIZED_EVENT } from '@/api/client'
import { ThemeContext, useThemeState } from '@/lib/theme'
import { createAppQueryClient } from './queryClient'

/** Any API call answered with 401 (outside of the auth endpoints) drops the cache and returns to the login page. */
function UnauthorizedSessionHandler() {
  const queryClient = useQueryClient()
  const navigate = useNavigate()

  useEffect(() => {
    const unauthorized = () => {
      queryClient.clear()
      navigate('/login', { replace: true })
    }
    window.addEventListener(UNAUTHORIZED_EVENT, unauthorized)
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, unauthorized)
  }, [navigate, queryClient])

  return null
}

function ThemeProvider({ children }: { children: ReactNode }) {
  const theme = useThemeState()
  return <ThemeContext value={theme}>{children}</ThemeContext>
}

export function Providers({ children }: { children: ReactNode }) {
  const [queryClient] = useState(createAppQueryClient)

  return (
    <ThemeProvider>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter basename="/ui">
          <UnauthorizedSessionHandler />
          {children}
        </BrowserRouter>
      </QueryClientProvider>
    </ThemeProvider>
  )
}
