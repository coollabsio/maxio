import { ChevronDown, LogOut, Settings } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { Link } from 'react-router'
import { cn } from '@/lib/utils'

function Divider() {
  return <div className="my-1 h-px bg-neutral-200 dark:bg-white/[0.07]" />
}

/** Account button at the bottom of the navbar. The menu opens upward, like Coolify's. */
export function UserMenu({
  collapsed,
  onLogout,
  name,
  detail,
}: {
  collapsed: boolean
  onLogout: () => void
  name: string
  detail: string
}) {
  const [open, setOpen] = useState(false)
  const root = useRef<HTMLDivElement>(null)
  const panelRef = useRef<HTMLDivElement>(null)
  const buttonRef = useRef<HTMLButtonElement>(null)
  const [panel, setPanel] = useState({ left: 0, bottom: 0, maxHeight: 240 })
  const initial = name.trim().charAt(0).toUpperCase() || 'A'

  function placePanel() {
    const rect = buttonRef.current?.getBoundingClientRect()
    if (!rect) return
    setPanel({
      left: rect.left,
      bottom: window.innerHeight - rect.top + 4,
      maxHeight: Math.max(rect.top - 12, 160),
    })
  }

  useEffect(() => {
    if (!open) return
    const closeOnOutsideClick = (event: PointerEvent) => {
      const target = event.target as Node
      if (!root.current?.contains(target) && !panelRef.current?.contains(target)) setOpen(false)
    }
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false)
    }
    document.addEventListener('pointerdown', closeOnOutsideClick)
    window.addEventListener('keydown', closeOnEscape)
    return () => {
      document.removeEventListener('pointerdown', closeOnOutsideClick)
      window.removeEventListener('keydown', closeOnEscape)
    }
  }, [open])

  return (
    <div ref={root} className={cn('relative', !collapsed && 'min-w-0 flex-1')}>
      <button
        ref={buttonRef}
        type="button"
        onClick={() => {
          if (open) {
            setOpen(false)
            return
          }
          placePanel()
          setOpen(true)
        }}
        title={name}
        aria-label={`Account menu for ${name}`}
        aria-expanded={open}
        className={cn(
          'button-3d inline-flex h-8 min-w-0 items-center gap-1.5 rounded-lg border border-neutral-200 bg-white px-2 text-[13px] font-medium text-black focus-visible:outline-none dark:text-fg',
          collapsed ? 'w-8 justify-center px-0' : 'w-full',
        )}
      >
        <span className="flex size-5 shrink-0 items-center justify-center rounded-full bg-neutral-200 text-[11px] font-semibold text-neutral-700 dark:bg-white/[0.1] dark:text-fg">
          {initial}
        </span>
        {collapsed ? null : (
          <>
            <span className="min-w-0 flex-1 truncate text-left text-xs font-medium">{name}</span>
            <ChevronDown
              className={cn('size-3.5 shrink-0 text-neutral-400 transition-transform dark:text-fg-faint', open && 'rotate-180')}
              aria-hidden="true"
            />
          </>
        )}
      </button>

      {open
        ? createPortal(
        <div
          ref={panelRef}
          className="listbox-panel top-user-menu-panel top-user-menu-panel-sidebar fixed origin-bottom-left"
          style={{ left: panel.left, bottom: panel.bottom, maxHeight: panel.maxHeight, zIndex: 90 }}
        >
          <div className="min-w-0 px-2 py-1.5">
            <div className="truncate text-[13px] font-semibold text-black dark:text-fg">{name}</div>
            <div className="truncate text-[11px] text-neutral-500 dark:text-fg-faint">{detail}</div>
          </div>
          <Divider />
          <Link to="/appearance" className="listbox-option" onClick={() => setOpen(false)}>
            <span className="flex items-center gap-2">
              <Settings className="size-4 opacity-80" aria-hidden="true" />
              Appearance
            </span>
          </Link>
          <Divider />
          <button
            type="button"
            className="listbox-option text-error"
            onClick={() => {
              setOpen(false)
              onLogout()
            }}
          >
            <span className="flex items-center gap-2">
              <LogOut className="size-4 opacity-90" aria-hidden="true" />
              Log out
            </span>
          </button>
        </div>,
        document.body,
      )
        : null}
    </div>
  )
}
