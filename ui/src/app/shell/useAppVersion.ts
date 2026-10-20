import { useEffect, useState } from 'react'

/** Version from `GET /maxio/api/version` after a console session exists. Empty until that call succeeds. */
export function useAppVersion(): string {
  const [version, setVersion] = useState('')

  useEffect(() => {
    // Bun unit tests do not set Vite's DEV/PROD flags. Skip the probe there.
    if (!import.meta.env.DEV && !import.meta.env.PROD) return
    const controller = new AbortController()
    fetch('/maxio/api/version', {
      signal: controller.signal,
      credentials: 'same-origin',
      headers: { accept: 'application/json' },
    })
      .then((response) => (response.ok ? response.json() : null))
      .then((body: { version?: unknown } | null) => {
        if (body && typeof body.version === 'string' && body.version.length > 0) {
          setVersion(body.version)
        }
      })
      .catch(() => {
        // Leave the badge blank when the session is missing or the probe fails.
      })
    return () => controller.abort()
  }, [])

  return version
}
