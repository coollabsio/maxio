import { beforeEach, expect, test } from 'bun:test'
import { act, renderHook } from '@testing-library/react'
import { useThemeState } from './theme'

beforeEach(() => {
  localStorage.clear()
  delete document.documentElement.dataset.navStyle
  delete document.documentElement.dataset.navItems
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
