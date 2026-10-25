import { expect, test } from 'bun:test'
import { isDarkColor, parseCustomTheme, readableTextOn, serializeCustomTheme } from './customTheme'

test('a share code is four hex colors and anything else is rejected', () => {
  expect(parseCustomTheme('#120e1a,#1c1c1c,#6b16ed,#0a0a0a')).toEqual({
    sidebar: '#120e1a',
    selected: '#1c1c1c',
    accent: '#6b16ed',
    background: '#0a0a0a',
  })
  expect(parseCustomTheme('nope')).toBeNull()
  expect(parseCustomTheme('#fff,#fff,#fff')).toBeNull()
})

test('serializing a theme round-trips through the share code', () => {
  const theme = { sidebar: '#3b1410', selected: '#8f2d1f', accent: '#ffb86b', background: '#241816' }
  expect(parseCustomTheme(serializeCustomTheme(theme))).toEqual(theme)
})

test('dark surfaces take light text and light surfaces take dark text', () => {
  expect(isDarkColor('#0a0a0a')).toBe(true)
  expect(readableTextOn('#0a0a0a')).toBe('#f4f4f5')
  expect(isDarkColor('#ffffff')).toBe(false)
  expect(readableTextOn('#ffffff')).toBe('#18181b')
})
