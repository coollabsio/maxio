import { Check } from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { Button } from '@/components/ui/button'
import { Dialog } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { PageHeader } from '@/components/ui/page-header'
import {
  THEME_PRESETS,
  normalizeHex,
  parseCustomTheme,
  sameCustomTheme,
  serializeCustomTheme,
  type CustomThemeColors,
} from '@/lib/customTheme'
import { useTheme, type NavItems, type NavStyle, type PageWidth, type ThemeMode } from '@/lib/theme'
import { cn } from '@/lib/utils'

const COOLIFY_SWATCH = THEME_PRESETS[0].swatch

function OptionCard({
  selected,
  label,
  description,
  onClick,
  children,
}: {
  selected: boolean
  label: string
  description: string
  onClick: () => void
  children: ReactNode
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={selected}
      className={cn(
        'group overflow-hidden rounded-[10px] border border-neutral-200 bg-white text-left transition-[border-color,box-shadow] hover:border-neutral-300 hover:shadow-sm dark:border-white/[0.07] dark:bg-white/[0.05] dark:hover:border-white/[0.12]',
        selected && 'border-brand bg-brand/6 ring-2 ring-brand/25 dark:border-brand-light dark:bg-brand-light/8 dark:ring-brand-light/25',
      )}
    >
      {children}
      <div className="p-3">
        <div className="flex items-center justify-between gap-2">
          <span className="text-sm font-semibold text-black dark:text-fg">{label}</span>
          {selected ? <Check className="size-4 text-coollabs dark:text-brand-light" aria-hidden="true" /> : null}
        </div>
        <p className="mt-1 text-xs leading-5 text-neutral-500 dark:text-fg-dim">{description}</p>
      </div>
    </button>
  )
}

function Preview({ className, children }: { className?: string; children?: React.ReactNode }) {
  return (
    <div className={cn('flex h-20 items-center justify-center border-b border-neutral-200 dark:border-white/[0.07]', className)}>
      {children}
    </div>
  )
}

function Swatch({ colors }: { colors: CustomThemeColors }) {
  return (
    <span className="flex h-12 w-24 overflow-hidden rounded-md border border-black/10 dark:border-white/10">
      <span className="w-2/5" style={{ background: colors.sidebar }} />
      <span className="flex w-3/5 flex-col">
        <span className="h-1/2" style={{ background: colors.background }} />
        <span className="h-1/2" style={{ background: colors.accent }} />
      </span>
    </span>
  )
}

const themeChoices: { value: ThemeMode; label: string; description: string; preview: string }[] = [
  { value: 'light', label: 'Light', description: 'Bright surfaces and dark text.', preview: 'bg-white' },
  {
    value: 'system',
    label: 'System',
    description: 'Follow your operating system.',
    preview: 'bg-linear-to-r from-white via-neutral-400 to-[#050505]',
  },
  { value: 'dark', label: 'Dark', description: 'Dark surfaces and soft contrast.', preview: 'bg-[#181818]' },
]

const widthChoices: { value: PageWidth; label: string; description: string }[] = [
  { value: 'full', label: 'Full width', description: 'Use all available space for page content.' },
  { value: 'centered', label: 'Centered', description: 'Keep content centered at a comfortable maximum width.' },
]

const navChoices: { value: NavStyle; label: string; description: string }[] = [
  { value: 'default', label: 'Default', description: 'Top bar and sidebars run edge to edge.' },
  { value: 'floating', label: 'Floating', description: 'Framed panels float on a dotted backdrop.' },
]

const styleChoices: { value: NavItems; label: string; description: string }[] = [
  { value: '3d', label: '3D', description: 'Buttons and sidebar icons sit on a raised edge that lifts on hover.' },
  { value: 'flat', label: 'Flat', description: 'No raised edges. Sidebar items are plain rows with a highlight for the current page.' },
]

const colorFields: { key: keyof CustomThemeColors; label: string; description: string }[] = [
  { key: 'sidebar', label: 'Sidebar', description: 'The navigation on the left' },
  { key: 'selected', label: 'Selected', description: 'The current page in the sidebar' },
  { key: 'accent', label: 'Accent', description: 'Buttons, links, and highlights' },
  { key: 'background', label: 'Background', description: 'Pages, cards, and panels' },
]

/** Coolify's Appearance page: theme, page width, navigation style, and item style. */
export function AppearancePage() {
  const theme = useTheme()
  const [dialogOpen, setDialogOpen] = useState(false)
  const [draft, setDraft] = useState<CustomThemeColors | null>(theme.customTheme)
  const [shareCode, setShareCode] = useState('')
  const [shareInvalid, setShareInvalid] = useState(false)
  const draftColors = draft ?? COOLIFY_SWATCH

  function openCustom() {
    const next = theme.mode === 'custom' ? theme.customTheme : null
    setDraft(next)
    setShareCode(serializeCustomTheme(next ?? COOLIFY_SWATCH))
    setShareInvalid(false)
    setDialogOpen(true)
  }

  function setDraftColor(key: keyof CustomThemeColors, value: string) {
    const next = parseCustomTheme(serializeCustomTheme({ ...draftColors, [key]: normalizeHex(value, draftColors[key]) }))
    if (!next) return
    setDraft(next)
    setShareCode(serializeCustomTheme(next))
    setShareInvalid(false)
  }

  function readShareCode(value: string) {
    setShareCode(value)
    const parsed = parseCustomTheme(value)
    if (parsed) {
      setDraft(parsed)
      setShareInvalid(false)
      return
    }
    setShareInvalid(value.trim() !== '')
  }

  function saveCustom() {
    setDialogOpen(false)
    if (draft === null) {
      theme.setTheme('dark')
      return
    }
    theme.setCustomThemeColors(draft)
  }

  return (
    <div className="flex w-full flex-col gap-6">
      <PageHeader title="Appearance" description="Choose how MaxIO looks in this browser." />

      <section className="settings-section">
        <div className="settings-section-header">
          <div>
            <h2>Color theme</h2>
            <p>Choose the color scheme used in this browser.</p>
          </div>
        </div>
        <div className="settings-section-body grid gap-3 p-4 sm:grid-cols-2 lg:grid-cols-4">
          {themeChoices.map((option) => (
            <OptionCard
              key={option.value}
              selected={theme.mode === option.value}
              label={option.label}
              description={option.description}
              onClick={() => theme.setTheme(option.value)}
            >
              <Preview className={option.preview}>
                <div className="h-8 w-20 rounded-md border border-black/10 bg-neutral-100/80 shadow-sm dark:border-white/10 dark:bg-black/20" />
              </Preview>
            </OptionCard>
          ))}
          <OptionCard
            selected={theme.mode === 'custom'}
            label="Custom"
            description="Pick a preset or your own colors."
            onClick={openCustom}
          >
            <Preview className="bg-neutral-100 dark:bg-black/20">
              <Swatch colors={theme.mode === 'custom' && theme.customTheme ? theme.customTheme : COOLIFY_SWATCH} />
            </Preview>
          </OptionCard>
        </div>
      </section>

      <section className="settings-section">
        <div className="settings-section-header">
          <div>
            <h2>Page width</h2>
            <p>Choose how content uses the available browser width.</p>
          </div>
        </div>
        <div className="settings-section-body grid gap-3 p-4 sm:grid-cols-2">
          {widthChoices.map((option) => (
            <OptionCard
              key={option.value}
              selected={theme.pageWidth === option.value}
              label={option.label}
              description={option.description}
              onClick={() => theme.setPageWidth(option.value)}
            >
              <Preview className="bg-neutral-50 px-4 dark:bg-black/15">
                <div className="flex h-11 w-full gap-1.5 rounded-md border border-neutral-300 bg-white p-1.5 dark:border-white/15 dark:bg-[#181818]">
                  <div className="w-3 shrink-0 rounded-sm bg-neutral-200 dark:bg-white/10" />
                  <div
                    className={cn(
                      'h-full rounded-sm bg-neutral-200 dark:bg-white/10',
                      option.value === 'full' ? 'w-full' : 'mx-auto w-2/3',
                    )}
                  />
                </div>
              </Preview>
            </OptionCard>
          ))}
        </div>
      </section>

      <section className="settings-section">
        <div className="settings-section-header">
          <div>
            <h2>Navigation style</h2>
            <p>Choose how the top bar and sidebars sit on the page.</p>
          </div>
        </div>
        <div className="settings-section-body grid gap-3 p-4 sm:grid-cols-2">
          {navChoices.map((option) => (
            <OptionCard
              key={option.value}
              selected={theme.navStyle === option.value}
              label={option.label}
              description={option.description}
              onClick={() => theme.setNavStyle(option.value)}
            >
              <Preview className={cn('bg-neutral-50 dark:bg-black/15', option.value === 'floating' && 'gap-1.5 p-1.5')}>
                <div
                  className={cn(
                    'flex h-full flex-col items-center justify-center gap-1.5 bg-white px-2 dark:bg-white/[0.04]',
                    option.value === 'floating'
                      ? 'rounded-lg border border-neutral-200 dark:border-white/[0.08]'
                      : 'border-r border-neutral-200 dark:border-white/[0.07]',
                  )}
                >
                  <span className="size-6 rounded-md border border-neutral-200 bg-neutral-50 dark:border-white/[0.08] dark:bg-white/[0.04]" />
                  <span className="size-6 rounded-md border border-neutral-200 bg-neutral-50 dark:border-white/[0.08] dark:bg-white/[0.04]" />
                </div>
              </Preview>
            </OptionCard>
          ))}
        </div>
      </section>

      <section className="settings-section">
        <div className="settings-section-header">
          <div>
            <h2>Style</h2>
            <p>Choose how buttons and sidebar items look.</p>
          </div>
        </div>
        <div className="settings-section-body grid gap-3 p-4 sm:grid-cols-2">
          {styleChoices.map((option) => (
            <OptionCard
              key={option.value}
              selected={theme.navItems === option.value}
              label={option.label}
              description={option.description}
              onClick={() => theme.setNavItems(option.value)}
            >
              <Preview className="flex-col gap-1.5 bg-neutral-50 px-4 dark:bg-black/15">
                <span
                  className={cn(
                    'size-6 rounded-md',
                    option.value === '3d'
                      ? 'border border-neutral-200 bg-white shadow-[0_2px_0_rgb(0_0_0/0.22)] dark:border-white/[0.09] dark:bg-white/[0.04]'
                      : 'bg-neutral-200/70 dark:bg-white/[0.08]',
                  )}
                />
                <span className="h-1.5 w-16 rounded-full bg-neutral-200 dark:bg-white/10" />
              </Preview>
            </OptionCard>
          ))}
        </div>
      </section>

      <Dialog
        open={dialogOpen}
        title="Custom theme"
        description="Colors of this console in this browser. Text stays readable on every color."
        onClose={() => setDialogOpen(false)}
        footer={
          <>
            <Button variant="default" onClick={() => setDialogOpen(false)}>
              Cancel
            </Button>
            <Button variant="highlighted" onClick={saveCustom}>
              Save theme
            </Button>
          </>
        }
      >
        <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)]">
          <div>
            <div className="mb-2 text-xs font-medium text-neutral-500 dark:text-fg-dim">Presets</div>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
              {THEME_PRESETS.map((preset) => {
                const selected = sameCustomTheme(draft, preset.colors)
                return (
                  <button
                    key={preset.name}
                    type="button"
                    aria-pressed={selected}
                    onClick={() => {
                      setDraft(preset.colors)
                      setShareCode(serializeCustomTheme(preset.colors ?? COOLIFY_SWATCH))
                      setShareInvalid(false)
                    }}
                    className="flex flex-col gap-1.5 rounded-lg p-1 text-left focus-visible:ring-1 focus-visible:ring-ring"
                  >
                    <span className={cn('rounded-md', selected && 'ring-2 ring-brand ring-offset-2 ring-offset-white dark:ring-brand-light dark:ring-offset-panel')}>
                      <Swatch colors={preset.swatch} />
                    </span>
                    <span className="truncate text-xs text-neutral-600 dark:text-fg-dim">{preset.name}</span>
                  </button>
                )
              })}
            </div>
          </div>
          <div className="flex flex-col gap-4">
            <div className="flex flex-col gap-2.5">
              {colorFields.map((field) => (
                <div key={field.key} className="flex items-center gap-3">
                  <label className="relative size-9 shrink-0 cursor-pointer overflow-hidden rounded-md border border-black/10 shadow-sm dark:border-white/15">
                    <span className="absolute inset-0" style={{ background: draftColors[field.key] }} />
                    <input
                      type="color"
                      aria-label={`${field.label} color`}
                      value={normalizeHex(draftColors[field.key])}
                      onChange={(event) => setDraftColor(field.key, event.target.value)}
                      className="absolute inset-0 h-full w-full cursor-pointer opacity-0"
                    />
                  </label>
                  <div className="min-w-0 flex-1">
                    <div className="text-sm font-medium text-black dark:text-fg">{field.label}</div>
                    <div className="truncate text-xs text-neutral-500 dark:text-fg-dim">{field.description}</div>
                  </div>
                  <Input
                    aria-label={`${field.label} hex color`}
                    value={draftColors[field.key]}
                    spellCheck={false}
                    maxLength={7}
                    onChange={(event) => setDraftColor(field.key, event.target.value)}
                    className="w-28 shrink-0 font-mono"
                  />
                </div>
              ))}
            </div>
            <div>
              <label htmlFor="custom-theme-share-code" className="mb-2 block text-xs font-medium text-neutral-500 dark:text-fg-dim">
                Share code
              </label>
              <Input
                id="custom-theme-share-code"
                value={shareCode}
                spellCheck={false}
                onChange={(event) => readShareCode(event.target.value)}
                aria-invalid={shareInvalid}
                className={cn('font-mono', shareInvalid && 'border-error')}
              />
              <p className={cn('mt-1.5 text-xs', shareInvalid ? 'text-error' : 'text-neutral-500 dark:text-fg-dim')}>
                {shareInvalid ? 'Enter four hex colors, separated by commas.' : 'Paste a code that someone shared, or copy yours.'}
              </p>
            </div>
          </div>
        </div>
      </Dialog>
    </div>
  )
}
