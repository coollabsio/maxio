// Renders the PWA / touch icons in public/ from public/logo.svg. Run: bun run icons
import { chromium } from '@playwright/test'

const svg = await Bun.file('public/logo.svg').text()
const background = '#101010' // dark console background (--cool-bg)

// [file, size, logo share of the canvas, opaque background]
const icons: [string, number, number, boolean][] = [
  ['favicon-32.png', 32, 1, false],
  ['apple-touch-icon.png', 180, 0.7, true],
  ['icon-192.png', 192, 0.75, true],
  ['icon-512.png', 512, 0.75, true],
  // Maskable: launchers crop to a circle, so keep the logo inside the 80% safe zone.
  ['icon-maskable-512.png', 512, 0.6, true],
]

const browser = await chromium.launch()
const page = await browser.newPage()
for (const [file, size, share, opaque] of icons) {
  const logo = Math.round(size * share)
  await page.setViewportSize({ width: size, height: size })
  await page.setContent(
    `<body style="margin:0;display:grid;place-items:center;width:${size}px;height:${size}px;background:${opaque ? background : 'transparent'}">` +
      svg.replace('<svg ', `<svg style="width:${logo}px;height:${logo}px" `) +
      '</body>',
  )
  await page.screenshot({ path: `public/${file}`, omitBackground: !opaque })
  console.log(`public/${file}`)
}
await browser.close()
