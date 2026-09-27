import { readFile } from 'node:fs/promises'
import { expect, request, test, type Page } from '@playwright/test'

// Every console feature against a real server (see playwright.config.ts).
const accessKey = process.env.MAXIO_E2E_ACCESS_KEY ?? 'maxioadmin'
const secretKey = process.env.MAXIO_E2E_SECRET_KEY ?? 'maxioadmin'

async function login(page: Page) {
  await page.goto('/ui')
  await expect(page).toHaveURL(/\/ui\/login$/)
  await page.getByLabel('Access Key').fill(accessKey)
  await page.locator('#secretKey').fill(secretKey)
  await page.getByRole('button', { name: 'Login' }).click()
  await expect(page.getByRole('heading', { name: 'Buckets' })).toBeVisible()
}

async function confirm(page: Page, dialogName: string, button: string, typed?: string) {
  const dialog = page.getByRole('dialog', { name: dialogName })
  if (typed) await dialog.getByRole('textbox').fill(typed)
  await dialog.getByRole('button', { name: button }).click()
  await expect(dialog).toBeHidden()
}

async function upload(page: Page, name: string, text: string) {
  await page.getByTestId('upload-input').setInputFiles({ name, mimeType: 'text/plain', buffer: Buffer.from(text) })
  await expect(page.getByText('File uploaded').last()).toBeVisible()
}

async function downloadText(page: Page, click: () => Promise<void>) {
  const [download] = await Promise.all([page.waitForEvent('download'), click()])
  return readFile(await download.path(), 'utf8')
}

test('all console features work end to end', async ({ page, baseURL }) => {
  const bucket = `features-${Date.now()}`
  const anonymous = await request.newContext({ baseURL })

  await login(page)

  // Create the bucket and open its settings.
  await page.getByRole('button', { name: 'Create Bucket' }).click()
  await page.getByRole('dialog', { name: 'Create bucket' }).getByLabel('Bucket name').fill(bucket)
  await confirm(page, 'Create bucket', 'Create bucket')
  await page.getByRole('row').filter({ hasText: bucket }).getByRole('button', { name: 'Bucket settings' }).click()
  await expect(page).toHaveURL(new RegExp(`/ui/buckets/${bucket}/settings$`))

  // Settings: versioning, encryption, public read + listing.
  await page.getByRole('switch', { name: 'Toggle versioning' }).click()
  await expect(page.getByText('Versioning enabled')).toBeVisible()
  await page.getByRole('switch', { name: 'Toggle default encryption' }).click()
  await expect(page.getByText('Default encryption enabled')).toBeVisible()
  await page.getByRole('switch', { name: 'Toggle public read' }).click()
  await confirm(page, 'Enable public read?', 'Enable public read')
  await page.getByRole('switch', { name: 'Toggle public listing' }).click()
  await confirm(page, 'Enable public listing?', 'Enable public listing')

  // A reload on a deep link keeps the page and the saved state.
  await page.reload()
  for (const name of ['Toggle versioning', 'Toggle default encryption', 'Toggle public read', 'Toggle public listing']) {
    await expect(page.getByRole('switch', { name })).toBeChecked()
  }

  // Folder + nested upload + breadcrumbs.
  await page.getByRole('navigation', { name: 'Breadcrumb' }).getByRole('button', { name: bucket }).click()
  await page.getByRole('button', { name: 'New Folder' }).click()
  await page.getByRole('dialog', { name: 'Create folder' }).getByLabel('Folder name').fill('docs')
  await confirm(page, 'Create folder', 'Create folder')
  await page.getByRole('cell', { name: 'docs/' }).click()
  await expect(page).toHaveURL(/prefix=docs/)
  await upload(page, 'report v1.txt', 'first version\n')
  await upload(page, 'report v1.txt', 'second version\n')
  const fileRow = page.getByRole('row').filter({ hasText: 'report v1.txt' })

  // Download.
  expect(await downloadText(page, () => fileRow.getByRole('link', { name: 'Download' }).click())).toBe('second version\n')

  // Presigned URL works without a session.
  await fileRow.getByRole('button', { name: 'Copy presigned URL' }).click()
  await page.getByRole('menuitem', { name: '1 hour' }).click()
  await expect(page.getByText('Presigned URL copied to clipboard')).toBeVisible()
  const presigned = await page.evaluate(() => navigator.clipboard.readText())
  expect(presigned).toContain('X-Amz-Expires=3600')
  expect(await (await anonymous.get(presigned)).text()).toBe('second version\n')

  // Public read (anonymous GET) with default encryption on.
  const publicObject = await anonymous.get(`/${bucket}/docs/report%20v1.txt`)
  expect(publicObject.status()).toBe(200)
  expect(await publicObject.text()).toBe('second version\n')

  // Version history: two versions, download the old one, delete it.
  await fileRow.getByRole('button', { name: 'Version history' }).click()
  const versionRows = page
    .getByRole('row')
    .filter({ has: page.getByRole('link', { name: 'Download this version' }) })
    .filter({ hasNot: page.getByRole('table') }) // not the outer row that holds the version table
  await expect(versionRows).toHaveCount(2)
  expect(await downloadText(page, () => versionRows.nth(1).getByRole('link', { name: 'Download this version' }).click())).toBe(
    'first version\n',
  )
  await versionRows.nth(1).getByRole('button', { name: 'Permanently delete this version' }).click()
  await confirm(page, 'Permanently delete version?', 'Delete version', 'delete')
  await expect(versionRows).toHaveCount(1)

  // Delete the file: the empty folder stays, then delete the folder.
  await fileRow.first().getByRole('button', { name: 'Delete', exact: true }).click()
  await confirm(page, 'Delete object?', 'Delete object')
  await page.getByRole('navigation', { name: 'Breadcrumb' }).getByRole('button', { name: bucket }).click()
  const folderRow = page.getByRole('row').filter({ hasText: 'docs/' })
  await folderRow.getByRole('button', { name: 'Delete empty folder' }).click()
  await confirm(page, 'Delete empty folder?', 'Delete folder')
  await expect(folderRow).toHaveCount(0)

  // Theme switch.
  await page.getByRole('button', { name: 'Use Dark theme' }).click()
  await expect(page.locator('html')).toHaveClass(/dark/)
  await page.getByRole('button', { name: 'Use Light theme' }).click()
  await expect(page.locator('html')).not.toHaveClass(/dark/)

  // Logout ends the session.
  await page.getByRole('button', { name: 'Sign out' }).click()
  await expect(page).toHaveURL(/\/ui\/login$/)
  await page.goto('/ui/')
  await expect(page).toHaveURL(/\/ui\/login$/)

  await anonymous.dispose()
})
