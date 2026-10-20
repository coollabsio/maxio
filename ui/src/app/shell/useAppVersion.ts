import { useEffect, useState } from 'react'
import { appVersion } from '@/version'

/** Cargo version compiled into the console, replaced by `GET /version` when the server answers. */
export function useAppVersion(): string {
  const [version, setVersion] = useState(appVersion)

  useEffect(() => {
    // Bun unit tests do not set Vite's DEV/PROD flags. Skip the probe there.
    if (!import.meta.env.DEV && !import.meta.env.PROD) return
    const controller = new AbortController()
    fetch('/version', { signal: controller.signal, headers: { accept: 'application/json' } })
      .then((response) => (response.ok ? response.json() : null))
      .then((body: { version?: unknown } | null) => {
        if (body && typeof body.version === 'string' && body.version.length > 0) {
          setVersion(body.version)
        }
      })
      .catch(() => {
        // The compiled version stays on screen when the probe is unreachable.
      })
    return () => controller.abort()
  }, [])

  return version
}
