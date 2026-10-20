/** When a restored or refocused page should ask `/maxio/api/auth/check` again. */
export function shouldRecheckSession(event: {
  type: string
  persisted?: boolean
  visibilityState?: string
}): boolean {
  if (event.type === 'pageshow') return event.persisted === true
  if (event.type === 'visibilitychange') return event.visibilityState === 'visible'
  if (event.type === 'focus') return true
  return false
}
