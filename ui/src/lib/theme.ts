import { createContext, useContext, useLayoutEffect, useState } from 'react'
import {
  applyCustomThemeProperties,
  clearCustomThemeProperties,
  isDarkColor,
  parseCustomTheme,
  serializeCustomTheme,
  type CustomThemeColors,
} from './customTheme'

export type ThemeMode = 'light' | 'system' | 'dark' | 'custom'
/** `floating` draws the top bar and sidebar as framed panels over a dotted backdrop. */
export type NavStyle = 'default' | 'floating'
/** `3d` puts each sidebar icon in a raised tile; `flat` shows plain rows. */
export type NavItems = '3d' | 'flat'
/** `centered` caps the page at 1400px; `full` uses the width of the window. */
export type PageWidth = 'centered' | 'full'

export const THEME_STORAGE_KEY = 'theme'
export const CUSTOM_THEME_STORAGE_KEY = 'customTheme'
export const PAGE_WIDTH_STORAGE_KEY = 'pageWidth'

export function isThemeMode(value: string | null): value is ThemeMode {
  return value === 'light' || value === 'system' || value === 'dark' || value === 'custom'
}

function readStoredTheme(): ThemeMode {
  try {
    const saved = localStorage.getItem(THEME_STORAGE_KEY)
    // Older Coolify builds stored the custom theme as "purple".
    if (saved === 'purple') return 'custom'
    return isThemeMode(saved) ? saved : 'dark'
  } catch {
    return 'dark'
  }
}

function readStoredCustomTheme(): CustomThemeColors | null {
  try {
    return parseCustomTheme(localStorage.getItem(CUSTOM_THEME_STORAGE_KEY))
  } catch {
    return null
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
 * Appearance of this browser, persisted in localStorage the way Coolify does:
 * theme (`dark` by default), custom colors, page width, navigation style, and
 * navigation items. The same values are applied to `<html>` before paint by `index.html`.
 */
export function useThemeState(): ThemeState {
  const [mode, setMode] = useState<ThemeMode>(readStoredTheme)
  const [customTheme, setCustomTheme] = useState<CustomThemeColors | null>(readStoredCustomTheme)
  const [navStyle, setNavStyleState] = useState(() => readStored<NavStyle>('navStyle', ['default', 'floating'], 'default'))
  const [navItems, setNavItemsState] = useState(() => readStored<NavItems>('navItems', ['3d', 'flat'], '3d'))
  const [pageWidth, setPageWidthState] = useState(() => readStored<PageWidth>(PAGE_WIDTH_STORAGE_KEY, ['centered', 'full'], 'centered'))
  const [systemDark, setSystemDark] = useState(systemPrefersDark)
  const customIsDark = customTheme ? isDarkColor(customTheme.background) : true
  const isDark = mode === 'dark' || (mode === 'system' && systemDark) || (mode === 'custom' && customIsDark)

  useLayoutEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)')
    const onChange = () => setSystemDark(mediaQuery.matches)
    mediaQuery.addEventListener('change', onChange)
    return () => mediaQuery.removeEventListener('change', onChange)
  }, [])

  useLayoutEffect(() => {
    const root = document.documentElement
    root.dataset.navStyle = navStyle
    root.dataset.navItems = navItems
    if (mode === 'custom' && customTheme) {
      applyCustomThemeProperties(customTheme)
      return
    }
    clearCustomThemeProperties()
    const dark = mode === 'dark' || mode === 'custom' || (mode === 'system' && systemDark)
    root.classList.toggle('dark', dark)
    root.dataset.theme = dark ? 'dark' : 'light'
  }, [mode, customTheme, navStyle, navItems, systemDark])

  function setTheme(next: ThemeMode) {
    setMode(next)
    store(THEME_STORAGE_KEY, next)
  }

  function setCustomThemeColors(next: CustomThemeColors) {
    setCustomTheme(next)
    store(CUSTOM_THEME_STORAGE_KEY, serializeCustomTheme(next))
    setTheme('custom')
  }

  function setNavStyle(next: NavStyle) {
    setNavStyleState(next)
    store('navStyle', next)
  }

  function setNavItems(next: NavItems) {
    setNavItemsState(next)
    store('navItems', next)
  }

  function setPageWidth(next: PageWidth) {
    setPageWidthState(next)
    store(PAGE_WIDTH_STORAGE_KEY, next)
  }

  return {
    mode,
    isDark,
    setTheme,
    customTheme,
    setCustomThemeColors,
    navStyle,
    setNavStyle,
    navItems,
    setNavItems,
    pageWidth,
    setPageWidth,
  }
}

export interface ThemeState {
  mode: ThemeMode
  isDark: boolean
  setTheme: (mode: ThemeMode) => void
  customTheme: CustomThemeColors | null
  setCustomThemeColors: (theme: CustomThemeColors) => void
  navStyle: NavStyle
  setNavStyle: (style: NavStyle) => void
  navItems: NavItems
  setNavItems: (items: NavItems) => void
  pageWidth: PageWidth
  setPageWidth: (width: PageWidth) => void
}

export const ThemeContext = createContext<ThemeState | null>(null)

export function useTheme(): ThemeState {
  const theme = useContext(ThemeContext)
  if (!theme) throw new Error('useTheme must be used inside <ThemeProvider>')
  return theme
}
