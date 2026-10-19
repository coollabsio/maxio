import { Check, ChevronDown, LogOut } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { useTheme, type NavItems, type NavStyle, type ThemeMode } from '@/lib/theme'
import { cn } from '@/lib/utils'

const optionClass =
  'flex h-8 w-full items-center justify-between gap-2 rounded-md px-2 text-left text-xs text-neutral-600 transition-colors hover:bg-neutral-200 hover:text-neutral-950 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring dark:text-fg-dim dark:hover:bg-white/[0.06] dark:hover:text-fg'

function Divider() {
  return <div className="my-1 h-px bg-neutral-200 dark:bg-white/[0.07]" />
}

function SectionLabel({ children }: { children: string }) {
  return (
    <div className="px-2 pt-1 pb-0.5 text-[10px] font-medium tracking-wide text-neutral-400 uppercase dark:text-fg-faint">
      {children}
    </div>
  )
}

function Choice<T extends string>({
  options,
  value,
  onChange,
  label,
}: {
  options: { value: T; label: string }[]
  value: T
  onChange: (value: T) => void
  label: (option: string) => string
}) {
  return options.map((option) => (
    <button
      key={option.value}
      type="button"
      className={optionClass}
      aria-label={label(option.label)}
      aria-pressed={value === option.value}
      onClick={() => onChange(option.value)}
    >
      <span>{option.label}</span>
      {value === option.value ? <Check className="size-3.5 text-black dark:text-fg" aria-hidden="true" /> : null}
    </button>
  ))
}

const themeOptions: { value: ThemeMode; label: string }[] = [
  { value: 'light', label: 'Light' },
  { value: 'system', label: 'System' },
  { value: 'dark', label: 'Dark' },
]

const navStyleOptions: { value: NavStyle; label: string }[] = [
  { value: 'default', label: 'Default' },
  { value: 'floating', label: 'Floating' },
]

const navItemsOptions: { value: NavItems; label: string }[] = [
  { value: '3d', label: '3D' },
  { value: 'flat', label: 'Flat' },
]

/** Account button at the bottom of the sidebar. Its menu holds the appearance options and Sign out. */
export function UserMenu({ collapsed, onLogout }: { collapsed: boolean; onLogout: () => void }) {
  const [open, setOpen] = useState(false)
  const root = useRef<HTMLDivElement>(null)
  const theme = useTheme()

  useEffect(() => {
    if (!open) return
    const closeOnOutsideClick = (event: PointerEvent) => {
      if (!root.current?.contains(event.target as Node)) setOpen(false)
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
        type="button"
        onClick={() => setOpen(!open)}
        title="Account"
        aria-label="Account menu"
        aria-expanded={open}
        className={cn(
          'button-3d inline-flex h-8 min-w-0 items-center gap-1.5 rounded-lg border border-neutral-200 bg-control px-2 text-[13px] font-medium text-black transition-colors hover:bg-control-hover focus-visible:outline-none dark:border-white/[0.08] dark:text-fg',
          collapsed ? 'w-8 justify-center px-0' : 'w-full',
        )}
      >
        <span className="flex size-5 shrink-0 items-center justify-center rounded-full bg-neutral-200 text-[11px] font-semibold text-neutral-700 dark:bg-white/[0.1] dark:text-fg">
          A
        </span>
        {collapsed ? null : (
          <>
            <span className="min-w-0 flex-1 truncate text-left text-xs font-medium">Admin</span>
            <ChevronDown
              className={cn('size-3.5 shrink-0 text-neutral-400 transition-transform dark:text-fg-faint', open && 'rotate-180')}
              aria-hidden="true"
            />
          </>
        )}
      </button>

      {open ? (
        <div className="absolute bottom-full left-0 z-[90] mb-1 flex w-52 origin-bottom-left animate-in flex-col gap-px rounded-[10px] border border-line bg-white p-1 shadow-dropdown fade-in-0 zoom-in-95 dark:bg-coolgray-200">
          <div className="min-w-0 px-2 py-1.5">
            <div className="truncate text-[13px] font-semibold text-black dark:text-fg">Admin</div>
            <div className="truncate text-[11px] text-neutral-500 dark:text-fg-faint">Root credentials</div>
          </div>
          <Divider />
          <SectionLabel>Theme</SectionLabel>
          <Choice options={themeOptions} value={theme.mode} onChange={theme.setTheme} label={(name) => `Use ${name} theme`} />
          <Divider />
          <SectionLabel>Navigation</SectionLabel>
          <Choice
            options={navStyleOptions}
            value={theme.navStyle}
            onChange={theme.setNavStyle}
            label={(name) => `${name} navigation`}
          />
          <Divider />
          <SectionLabel>Navigation items</SectionLabel>
          <Choice
            options={navItemsOptions}
            value={theme.navItems}
            onChange={theme.setNavItems}
            label={(name) => `${name} navigation items`}
          />
          <Divider />
          <button
            type="button"
            className={cn(optionClass, 'justify-start text-[13px]')}
            onClick={() => {
              setOpen(false)
              onLogout()
            }}
          >
            <LogOut className="size-4 opacity-80" aria-hidden="true" />
            Sign out
          </button>
        </div>
      ) : null}
    </div>
  )
}
