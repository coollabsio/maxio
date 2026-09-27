const SIDEBAR_STORAGE_KEY = 'sidebar-collapsed'

export function readSidebarCollapsed(): boolean {
  try {
    return localStorage.getItem(SIDEBAR_STORAGE_KEY) === 'true'
  } catch {
    return false
  }
}

export function storeSidebarCollapsed(collapsed: boolean) {
  try {
    localStorage.setItem(SIDEBAR_STORAGE_KEY, String(collapsed))
  } catch {
    // Storage may be unavailable; the sidebar state then only lasts for this page load.
  }
}
