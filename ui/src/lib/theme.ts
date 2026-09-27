import { createContext, useContext, useEffect, useState } from 'react'

export type ThemeMode = 'light' | 'system' | 'dark'

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

function systemPrefersDark(): boolean {
  return window.matchMedia('(prefers-color-scheme: dark)').matches
}

/** Light / system / dark theme, persisted in localStorage and applied as `.dark` on `<html>`. */
export function useThemeState(): ThemeState {
  const [mode, setMode] = useState<ThemeMode>(readStoredTheme)
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

  function setTheme(next: ThemeMode) {
    setMode(next)
    try {
      localStorage.setItem(THEME_STORAGE_KEY, next)
    } catch {
      // Storage may be unavailable (private mode); the theme still applies for this session.
    }
  }

  return { mode, isDark, setTheme }
}

export interface ThemeState {
  mode: ThemeMode
  isDark: boolean
  setTheme: (mode: ThemeMode) => void
}

export const ThemeContext = createContext<ThemeState | null>(null)

export function useTheme(): ThemeState {
  const theme = useContext(ThemeContext)
  if (!theme) throw new Error('useTheme must be used inside <ThemeProvider>')
  return theme
}
