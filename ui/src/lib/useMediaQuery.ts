import { useSyncExternalStore } from 'react'

/** Tracks a CSS media query, e.g. `useMediaQuery('(min-width: 768px)')`. */
export function useMediaQuery(query: string): boolean {
  return useSyncExternalStore(
    (onChange) => {
      const list = window.matchMedia(query)
      list.addEventListener('change', onChange)
      return () => list.removeEventListener('change', onChange)
    },
    () => window.matchMedia(query).matches,
  )
}

/** Tailwind `md` breakpoint: the sidebar is a drawer below it. */
export const DESKTOP_QUERY = '(min-width: 768px)'
