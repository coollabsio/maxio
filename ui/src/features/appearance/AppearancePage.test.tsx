import { beforeEach, expect, test } from 'bun:test'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ReactNode } from 'react'
import { MemoryRouter } from 'react-router'
import { ThemeContext, useThemeState } from '@/lib/theme'
import { AppearancePage } from './AppearancePage'

function Theme({ children }: { children: ReactNode }) {
  return <ThemeContext value={useThemeState()}>{children}</ThemeContext>
}

function renderPage() {
  const queryClient = new QueryClient()
  return render(
    <Theme>
      <QueryClientProvider client={queryClient}>
        <MemoryRouter>
          <AppearancePage />
        </MemoryRouter>
      </QueryClientProvider>
    </Theme>,
  )
}

beforeEach(() => {
  localStorage.clear()
  document.documentElement.className = ''
  document.documentElement.removeAttribute('style')
  delete document.documentElement.dataset.theme
  delete document.documentElement.dataset.navStyle
  delete document.documentElement.dataset.navItems
})

test('light, floating, and flat choices change the theme the way Coolify does', async () => {
  const user = userEvent.setup()
  const screen = renderPage()
  expect(document.documentElement.classList.contains('dark')).toBe(true)

  await user.click(screen.getByRole('button', { name: /Light/ }))
  expect(document.documentElement.classList.contains('dark')).toBe(false)
  expect(document.documentElement.dataset.theme).toBe('light')
  expect(localStorage.getItem('theme')).toBe('light')

  await user.click(screen.getByRole('button', { name: /Floating/ }))
  expect(document.documentElement.dataset.navStyle).toBe('floating')

  await user.click(screen.getByRole('button', { name: /^Flat/ }))
  expect(document.documentElement.dataset.navItems).toBe('flat')

  await user.click(screen.getByRole('button', { name: /Full width/ }))
  expect(localStorage.getItem('pageWidth')).toBe('full')
})
