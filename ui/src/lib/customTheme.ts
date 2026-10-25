/** Coolify Appearance custom theme: four hex colors and the text that stays readable on each. */

export interface CustomThemeColors {
  sidebar: string
  selected: string
  accent: string
  background: string
}

export const CUSTOM_THEME_KEYS = ['sidebar', 'selected', 'accent', 'background'] as const

/** Built-in Dark theme, shown first. `colors: null` means "use the Dark theme", not a custom one. */
export const THEME_PRESETS: { name: string; colors: CustomThemeColors | null; swatch: CustomThemeColors }[] = [
  {
    name: 'Coolify',
    colors: null,
    swatch: { sidebar: '#2c1114', selected: '#1c1c1c', accent: '#e8333a', background: '#0a0a0a' },
  },
  {
    name: 'Midnight',
    colors: { sidebar: '#0f172a', selected: '#2e4a7d', accent: '#f2458f', background: '#1a2338' },
    swatch: { sidebar: '#0f172a', selected: '#2e4a7d', accent: '#f2458f', background: '#1a2338' },
  },
  {
    name: 'Forest',
    colors: { sidebar: '#12342b', selected: '#2c6e57', accent: '#f4b860', background: '#1b2a25' },
    swatch: { sidebar: '#12342b', selected: '#2c6e57', accent: '#f4b860', background: '#1b2a25' },
  },
  {
    name: 'Ember',
    colors: { sidebar: '#3b1410', selected: '#8f2d1f', accent: '#ffb86b', background: '#241816' },
    swatch: { sidebar: '#3b1410', selected: '#8f2d1f', accent: '#ffb86b', background: '#241816' },
  },
  {
    name: 'Slate',
    colors: { sidebar: '#2b3038', selected: '#4a5361', accent: '#6cc4f5', background: '#353b45' },
    swatch: { sidebar: '#2b3038', selected: '#4a5361', accent: '#6cc4f5', background: '#353b45' },
  },
  {
    name: 'Nord',
    colors: { sidebar: '#2e3440', selected: '#4c566a', accent: '#88c0d0', background: '#3b4252' },
    swatch: { sidebar: '#2e3440', selected: '#4c566a', accent: '#88c0d0', background: '#3b4252' },
  },
  {
    name: 'Dracula',
    colors: { sidebar: '#21222c', selected: '#44475a', accent: '#bd93f9', background: '#282a36' },
    swatch: { sidebar: '#21222c', selected: '#44475a', accent: '#bd93f9', background: '#282a36' },
  },
  {
    name: 'GitHub Dark',
    colors: { sidebar: '#010409', selected: '#21262d', accent: '#2f81f7', background: '#0d1117' },
    swatch: { sidebar: '#010409', selected: '#21262d', accent: '#2f81f7', background: '#0d1117' },
  },
  {
    name: 'Aubergine',
    colors: { sidebar: '#3f0e40', selected: '#1164a3', accent: '#1164a3', background: '#ffffff' },
    swatch: { sidebar: '#3f0e40', selected: '#1164a3', accent: '#1164a3', background: '#ffffff' },
  },
  {
    name: 'GitHub Light',
    colors: { sidebar: '#f6f8fa', selected: '#dde4ec', accent: '#0969da', background: '#ffffff' },
    swatch: { sidebar: '#f6f8fa', selected: '#dde4ec', accent: '#0969da', background: '#ffffff' },
  },
  {
    name: 'Paper',
    colors: { sidebar: '#ebe6da', selected: '#d9d1bf', accent: '#c2410c', background: '#f7f4ec' },
    swatch: { sidebar: '#ebe6da', selected: '#d9d1bf', accent: '#c2410c', background: '#f7f4ec' },
  },
  {
    name: 'Blossom',
    colors: { sidebar: '#fde8f1', selected: '#f9c4dc', accent: '#d61f69', background: '#fff7fa' },
    swatch: { sidebar: '#fde8f1', selected: '#f9c4dc', accent: '#d61f69', background: '#fff7fa' },
  },
]

const BRAND = '#e8333a'

export function normalizeHex(color: string | null | undefined, fallback = BRAND): string {
  const hex = String(color ?? '')
    .trim()
    .replace(/^#/, '')
    .toLowerCase()
  if (/^[a-f\d]{6}$/.test(hex)) return `#${hex}`
  if (/^[a-f\d]{3}$/.test(hex)) return `#${hex.replace(/./g, '$&$&')}`
  return fallback
}

function strictHex(color: string): string | null {
  const hex = color.trim().replace(/^#/, '').toLowerCase()
  if (/^[a-f\d]{6}$/.test(hex)) return `#${hex}`
  if (/^[a-f\d]{3}$/.test(hex)) return `#${hex.replace(/./g, '$&$&')}`
  return null
}

function channel(hex: string, index: number): number {
  return parseInt(normalizeHex(hex).slice(1 + index * 2, 3 + index * 2), 16)
}

function srgbToLinear(value: number): number {
  const c = value / 255
  return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4
}

function relativeLuminance(hex: string): number {
  const [r, g, b] = [0, 1, 2].map((index) => srgbToLinear(channel(hex, index)))
  return 0.2126 * r + 0.7152 * g + 0.0722 * b
}

/** Light text wins on this color (WCAG), the same test Coolify uses. */
export function isDarkColor(hex: string): boolean {
  const luminance = relativeLuminance(normalizeHex(hex))
  return 1.05 / (luminance + 0.05) >= (luminance + 0.05) / (relativeLuminance('#18181b') + 0.05)
}

export function readableTextOn(hex: string): string {
  return isDarkColor(hex) ? '#f4f4f5' : '#18181b'
}

/** Text on a brand fill: black on a light accent, white on a dark one. */
export function accentForeground(hex: string): string {
  const channels = [0, 1, 2].map((index) => channel(hex, index) * 0.85 + 255 * 0.15)
  const luminance = channels
    .map((value) => srgbToLinear(value))
    .reduce((sum, value, index) => sum + value * [0.2126, 0.7152, 0.0722][index], 0)
  return luminance > 0.179 ? '#111111' : '#ffffff'
}

export function mixHex(from: string, to: string, amount: number): string {
  const mixed = [0, 1, 2].map((index) => {
    const start = channel(from, index)
    const end = channel(to, index)
    return Math.round(start + (end - start) * amount)
      .toString(16)
      .padStart(2, '0')
  })
  return `#${mixed.join('')}`
}

export function serializeCustomTheme(theme: CustomThemeColors): string {
  return CUSTOM_THEME_KEYS.map((key) => normalizeHex(theme[key])).join(',')
}

export function parseCustomTheme(code: string | null | undefined): CustomThemeColors | null {
  const colors = String(code ?? '')
    .split(/[\s,]+/)
    .filter(Boolean)
    .map(strictHex)
  if (colors.length !== 4 || colors.some((color) => color === null)) return null
  return {
    sidebar: colors[0]!,
    selected: colors[1]!,
    accent: colors[2]!,
    background: colors[3]!,
  }
}

export function sameCustomTheme(a: CustomThemeColors | null, b: CustomThemeColors | null): boolean {
  if (a === null || b === null) return a === b
  return serializeCustomTheme(a) === serializeCustomTheme(b)
}

const CUSTOM_PROPERTIES = [
  '--theme-bg',
  '--theme-text',
  '--theme-sidebar',
  '--theme-sidebar-text',
  '--theme-selected',
  '--theme-selected-text',
  '--theme-accent',
  '--theme-accent-foreground',
  '--color-brand',
  '--color-brand-hover',
  '--color-brand-press',
  '--color-brand-depth',
  '--color-brand-light',
  '--color-brand-ring',
  '--color-brand-foreground',
] as const

/** Paint a custom theme onto `<html>`. Call `clearCustomThemeProperties` when leaving it. */
export function applyCustomThemeProperties(theme: CustomThemeColors) {
  const root = document.documentElement
  const accent = normalizeHex(theme.accent)
  const foreground = accentForeground(accent)
  const values: Record<(typeof CUSTOM_PROPERTIES)[number], string> = {
    '--theme-bg': normalizeHex(theme.background, '#0a0a0a'),
    '--theme-text': readableTextOn(theme.background),
    '--theme-sidebar': normalizeHex(theme.sidebar, '#1a0e10'),
    '--theme-sidebar-text': readableTextOn(theme.sidebar),
    '--theme-selected': normalizeHex(theme.selected, '#1c1c1c'),
    '--theme-selected-text': readableTextOn(theme.selected),
    '--theme-accent': accent,
    '--theme-accent-foreground': foreground,
    '--color-brand': accent,
    '--color-brand-hover': mixHex(accent, '#ffffff', 0.14),
    '--color-brand-press': mixHex(accent, '#000000', 0.18),
    '--color-brand-depth': mixHex(accent, '#000000', 0.38),
    '--color-brand-light': mixHex(accent, '#ffffff', 0.42),
    '--color-brand-ring': mixHex(accent, '#ffffff', 0.28),
    '--color-brand-foreground': foreground,
  }
  for (const [name, value] of Object.entries(values)) root.style.setProperty(name, value)
  const pageDark = isDarkColor(theme.background)
  const sidebarDark = isDarkColor(theme.sidebar)
  root.classList.toggle('dark', pageDark)
  root.dataset.theme = 'custom'
  if (sidebarDark === pageDark) delete root.dataset.sidebarScheme
  else root.dataset.sidebarScheme = sidebarDark ? 'dark' : 'light'
}

export function clearCustomThemeProperties() {
  const root = document.documentElement
  for (const name of CUSTOM_PROPERTIES) root.style.removeProperty(name)
  delete root.dataset.sidebarScheme
}
