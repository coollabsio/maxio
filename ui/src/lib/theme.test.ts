import { beforeEach, expect, test } from 'bun:test'
import { act, renderHook } from '@testing-library/react'
import { useThemeState } from './theme'

beforeEach(() => {
  localStorage.clear()
  document.documentElement.className = ''
  document.documentElement.removeAttribute('style')
  delete document.documentElement.dataset.navStyle
  delete document.documentElement.dataset.navItems
  delete document.documentElement.dataset.theme
  delete document.documentElement.dataset.sidebarScheme
})

test('navigation style and items default to the edge-to-edge bars with 3D items', () => {
  const { result } = renderHook(() => useThemeState())
  expect(result.current.navStyle).toBe('default')
  expect(result.current.navItems).toBe('3d')
  expect(document.documentElement.dataset.navStyle).toBe('default')
  expect(document.documentElement.dataset.navItems).toBe('3d')
})

test('choosing floating navigation and flat items is applied to <html> and remembered', () => {
  const { result } = renderHook(() => useThemeState())
  act(() => {
    result.current.setNavStyle('floating')
    result.current.setNavItems('flat')
  })
  expect(document.documentElement.dataset.navStyle).toBe('floating')
  expect(document.documentElement.dataset.navItems).toBe('flat')
  expect(localStorage.getItem('navStyle')).toBe('floating')
  expect(localStorage.getItem('navItems')).toBe('flat')

  const reloaded = renderHook(() => useThemeState())
  expect(reloaded.result.current.navStyle).toBe('floating')
  expect(reloaded.result.current.navItems).toBe('flat')
})

test('unknown stored values fall back to the defaults', () => {
  localStorage.setItem('navStyle', 'sideways')
  localStorage.setItem('navItems', 'round')
  const { result } = renderHook(() => useThemeState())
  expect(result.current.navStyle).toBe('default')
  expect(result.current.navItems).toBe('3d')
})

test('dark is the default theme, matching Coolify', () => {
  const { result } = renderHook(() => useThemeState())
  expect(result.current.mode).toBe('dark')
  expect(result.current.isDark).toBe(true)
  expect(document.documentElement.classList.contains('dark')).toBe(true)
  expect(document.documentElement.dataset.theme).toBe('dark')
  expect(result.current.pageWidth).toBe('centered')
})

test('a custom theme paints its colors and a built-in theme clears them', () => {
  const { result } = renderHook(() => useThemeState())
  act(() => {
    result.current.setCustomThemeColors({
      sidebar: '#3b1410',
      selected: '#8f2d1f',
      accent: '#ffb86b',
      background: '#241816',
    })
  })
  expect(document.documentElement.dataset.theme).toBe('custom')
  expect(document.documentElement.style.getPropertyValue('--theme-sidebar')).toBe('#3b1410')
  expect(document.documentElement.style.getPropertyValue('--color-brand')).toBe('#ffb86b')
  expect(localStorage.getItem('theme')).toBe('custom')

  act(() => result.current.setTheme('light'))
  expect(document.documentElement.dataset.theme).toBe('light')
  expect(document.documentElement.classList.contains('dark')).toBe(false)
  expect(document.documentElement.style.getPropertyValue('--theme-sidebar')).toBe('')
})

test('page width is applied and remembered', () => {
  const { result } = renderHook(() => useThemeState())
  act(() => result.current.setPageWidth('full'))
  expect(localStorage.getItem('pageWidth')).toBe('full')
  const reloaded = renderHook(() => useThemeState())
  expect(reloaded.result.current.pageWidth).toBe('full')
})
