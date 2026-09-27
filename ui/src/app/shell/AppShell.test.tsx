import { afterEach, beforeEach, expect, test } from 'bun:test'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, render } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ReactNode } from 'react'
import { MemoryRouter, Route, Routes } from 'react-router'
import { ThemeContext, useThemeState } from '@/lib/theme'
import { AppShell } from './AppShell'

type HappyWindow = Window & { happyDOM: { setViewport: (viewport: { width: number; height: number }) => void } }
const happyDOM = (window as unknown as HappyWindow).happyDOM

function Theme({ children }: { children: ReactNode }) {
  return <ThemeContext value={useThemeState()}>{children}</ThemeContext>
}

function renderShell() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <Theme>
      <QueryClientProvider client={queryClient}>
        <MemoryRouter>
          <Routes>
            <Route element={<AppShell />}>
              <Route index element={<p>Bucket list</p>} />
            </Route>
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>
    </Theme>,
  )
}

// The shell reacts to viewport changes, so resize inside act().
const setViewport = (width: number, height: number) => act(() => happyDOM.setViewport({ width, height }))

beforeEach(() => setViewport(375, 800))
afterEach(() => setViewport(1024, 768))

test('on mobile the sidebar is a drawer opened by the burger button', async () => {
  const user = userEvent.setup()
  const screen = renderShell()
  const sidebar = screen.getByRole('navigation', { name: 'Main', hidden: true })
  expect(sidebar.hasAttribute('inert')).toBe(true)

  await user.click(screen.getByRole('button', { name: 'Open menu' }))
  expect(sidebar.hasAttribute('inert')).toBe(false)

  await user.keyboard('{Escape}')
  expect(sidebar.hasAttribute('inert')).toBe(true)

  await user.click(screen.getByRole('button', { name: 'Open menu' }))
  await user.click(screen.getByRole('button', { name: 'Close menu' }))
  expect(sidebar.hasAttribute('inert')).toBe(true)
})

test('on desktop the sidebar is always visible and there is no burger button', () => {
  setViewport(1280, 800)
  const screen = renderShell()
  expect(screen.getByRole('navigation', { name: 'Main' }).hasAttribute('inert')).toBe(false)
  expect(screen.queryByRole('button', { name: 'Open menu' })).toBeNull()
})
