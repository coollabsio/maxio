import { createContext, useContext, useEffect, useState } from 'react'

export type ThemeMode = 'light' | 'system' | 'dark'
/** `floating` draws the top bar and sidebar as framed panels over a dotted backdrop (Coolify v4.5). */
export type NavStyle = 'default' | 'floating'
/** `3d` puts each sidebar icon in a raised tile; `flat` shows plain rows. */
export type NavItems = '3d' | 'flat'

export const THEME_STORAGE_KEY = 'theme'

export function isThemeMode(value: string | null): value is ThemeMode {
  return value === 'light' || value === 'system' || value === 'dark'
}

function readStoredTheme(): ThemeMode {
  try {
    const saved = localStorage.getItem(THEME_STORAGE_KEY)
    return isThemeMode(saved) ? saved : 'system'
  } catch {
    return 'system'
  }
}

function readStored<T extends string>(key: string, values: readonly T[], fallback: T): T {
  try {
    const saved = localStorage.getItem(key)
    return values.find((value) => value === saved) ?? fallback
  } catch {
    return fallback
  }
}

function store(key: string, value: string) {
  try {
    localStorage.setItem(key, value)
  } catch {
    // Storage may be unavailable (private mode); the choice still applies for this session.
  }
}

function systemPrefersDark(): boolean {
  return window.matchMedia('(prefers-color-scheme: dark)').matches
}

/**
 * Appearance of this browser, persisted in localStorage: the light / system / dark theme (`.dark` on `<html>`)
 * and the navigation style and items (`data-nav-style` / `data-nav-items` on `<html>`, read by index.css).
 * index.html applies the same values before the first paint.
 */
export function useThemeState(): ThemeState {
  const [mode, setMode] = useState<ThemeMode>(readStoredTheme)
  const [navStyle, setNavStyleState] = useState(() => readStored<NavStyle>('navStyle', ['default', 'floating'], 'default'))
  const [navItems, setNavItemsState] = useState(() => readStored<NavItems>('navItems', ['3d', 'flat'], '3d'))
  const [systemDark, setSystemDark] = useState(systemPrefersDark)
  const isDark = mode === 'dark' || (mode === 'system' && systemDark)

  useEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)')
    const onChange = () => setSystemDark(mediaQuery.matches)
    mediaQuery.addEventListener('change', onChange)
    return () => mediaQuery.removeEventListener('change', onChange)
  }, [])

  useEffect(() => {
    document.documentElement.classList.toggle('dark', isDark)
  }, [isDark])

  useEffect(() => {
    document.documentElement.dataset.navStyle = navStyle
    document.documentElement.dataset.navItems = navItems
  }, [navStyle, navItems])

  function setTheme(next: ThemeMode) {
    setMode(next)
    store(THEME_STORAGE_KEY, next)
  }

  function setNavStyle(next: NavStyle) {
    setNavStyleState(next)
    store('navStyle', next)
  }

  function setNavItems(next: NavItems) {
    setNavItemsState(next)
    store('navItems', next)
  }

  return { mode, isDark, setTheme, navStyle, setNavStyle, navItems, setNavItems }
}

export interface ThemeState {
  mode: ThemeMode
  isDark: boolean
  setTheme: (mode: ThemeMode) => void
  navStyle: NavStyle
  setNavStyle: (style: NavStyle) => void
  navItems: NavItems
  setNavItems: (items: NavItems) => void
}

export const ThemeContext = createContext<ThemeState | null>(null)

export function useTheme(): ThemeState {
  const theme = useContext(ThemeContext)
  if (!theme) throw new Error('useTheme must be used inside <ThemeProvider>')
  return theme
}
