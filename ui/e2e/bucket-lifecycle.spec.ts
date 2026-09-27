import { expect, test } from '@playwright/test'

// Needs a running MaxIO server (see playwright.config.ts). Default credentials: maxioadmin / maxioadmin.
const accessKey = process.env.MAXIO_E2E_ACCESS_KEY ?? 'maxioadmin'
const secretKey = process.env.MAXIO_E2E_SECRET_KEY ?? 'maxioadmin'

test('login, create a bucket, upload a file, delete both', async ({ page }) => {
  const bucket = `e2e-${Date.now()}`
  const fileName = 'hello maxio.txt'

  await page.goto('/ui/')
  await expect(page).toHaveURL(/\/ui\/login$/)

  await page.getByLabel('Access Key').fill(accessKey)
  await page.getByLabel('Secret Key', { exact: false }).first().fill(secretKey)
  await page.getByRole('button', { name: 'Login' }).click()

  await expect(page).toHaveURL(/\/ui\/?$/)
  await expect(page.getByRole('heading', { name: 'Buckets' })).toBeVisible()

  // Create bucket
  await page.getByRole('button', { name: 'Create Bucket' }).click()
  const createDialog = page.getByRole('dialog', { name: 'Create bucket' })
  await createDialog.getByLabel('Bucket name').fill(bucket)
  await createDialog.getByRole('button', { name: 'Create bucket' }).click()
  await expect(createDialog).toBeHidden()

  // Open it
  await page.getByRole('cell', { name: bucket, exact: true }).click()
  await expect(page).toHaveURL(new RegExp(`/ui/buckets/${bucket}$`))
  await expect(page.getByText('This location is empty')).toBeVisible()

  // Upload a file
  await page.getByTestId('upload-input').setInputFiles({
    name: fileName,
    mimeType: 'text/plain',
    buffer: Buffer.from('hello from playwright\n'),
  })
  await expect(page.getByRole('cell', { name: fileName })).toBeVisible()

  // Delete the file
  const fileRow = page.getByRole('row').filter({ hasText: fileName })
  await fileRow.getByRole('button', { name: 'Delete', exact: true }).click()
  const deleteObjectDialog = page.getByRole('dialog', { name: 'Delete object?' })
  await deleteObjectDialog.getByRole('button', { name: 'Delete object' }).click()
  await expect(deleteObjectDialog).toBeHidden()
  await expect(page.getByText('This location is empty')).toBeVisible()

  // Delete the bucket
  await page.getByRole('navigation', { name: 'Breadcrumb' }).getByRole('button', { name: 'Buckets' }).click()
  const bucketRow = page.getByRole('row').filter({ hasText: bucket })
  await bucketRow.getByRole('button', { name: 'Delete bucket' }).click()
  const deleteBucketDialog = page.getByRole('dialog', { name: 'Delete bucket?' })
  await deleteBucketDialog.getByLabel('Bucket name').fill(bucket)
  await deleteBucketDialog.getByRole('button', { name: 'Delete bucket' }).click()
  await expect(deleteBucketDialog).toBeHidden()
  await expect(page.getByRole('cell', { name: bucket, exact: true })).toHaveCount(0)
})
