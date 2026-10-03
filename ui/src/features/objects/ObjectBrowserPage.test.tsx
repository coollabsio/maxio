import { afterEach, expect, test } from 'bun:test'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router'
import { ObjectBrowserPage } from './ObjectBrowserPage'

const realFetch = globalThis.fetch

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

const listing = {
  files: [
    { key: 'readme.txt', size: 5, lastModified: '2026-01-02T03:04:05Z', etag: '"a"', contentType: 'text/plain' },
    { key: 'bundle.zip', size: 9, lastModified: '2026-01-02T03:04:05Z', etag: '"b"', contentType: 'application/zip' },
  ],
  prefixes: [],
  emptyPrefixes: [],
}

function mockApi() {
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    if (url.includes('/download/readme.txt')) {
      return new Response('hello', { status: 200, headers: { 'Content-Type': 'text/plain' } })
    }
    if (url.includes('/versioning')) return json(200, { enabled: false })
    if (url.includes('/objects')) return json(200, listing)
    return json(404, { error: `unexpected request ${url}` })
  }) as typeof globalThis.fetch
}

function renderBrowser() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={['/buckets/docs']}>
        <Routes>
          <Route path="/buckets/:bucket" element={<ObjectBrowserPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

afterEach(() => {
  globalThis.fetch = realFetch
})

test('lists the content type and only offers preview for previewable files', async () => {
  mockApi()
  const screen = renderBrowser()

  const readme = within((await screen.findByText('readme.txt')).closest('tr')!)
  expect(readme.getByText('text/plain')).toBeTruthy()
  expect(readme.getByRole('button', { name: 'Preview' })).toBeTruthy()

  const zip = within(screen.getByText('bundle.zip').closest('tr')!)
  expect(zip.getByText('application/zip')).toBeTruthy()
  expect(zip.queryByRole('button', { name: 'Preview' })).toBeNull()
})

test('preview opens a dialog with the fetched text and a download link', async () => {
  mockApi()
  const user = userEvent.setup()
  const screen = renderBrowser()

  const readme = within((await screen.findByText('readme.txt')).closest('tr')!)
  await user.click(readme.getByRole('button', { name: 'Preview' }))

  const dialog = within(await screen.findByRole('dialog', { name: 'readme.txt' }))
  await waitFor(() => expect(dialog.getByText('hello')).toBeTruthy())
  expect(dialog.getByText('text/plain')).toBeTruthy()
  const download = dialog.getByRole('button', { name: 'Download' })
  expect(download.tagName).toBe('A')
  expect(download.getAttribute('href')).toBe('/api/buckets/docs/download/readme.txt')

  await user.click(dialog.getByRole('button', { name: 'Close preview' }))
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
})
