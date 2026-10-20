import { afterEach, expect, test } from 'bun:test'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router'
import { ObjectBrowserPage } from './ObjectBrowserPage'

const realFetch = globalThis.fetch

function json(body: unknown) {
  return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } })
}

afterEach(() => {
  globalThis.fetch = realFetch
})

function renderBrowser(capabilities: { putObject: boolean; deleteObject: boolean }) {
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const request = input as Request
    const url = new URL(request.url)
    if (url.pathname.includes('/capabilities')) {
      return json({ createBucket: false, deleteBucket: false, ...capabilities })
    }
    if (url.pathname.includes('/versioning')) return json({ enabled: false })
    return json({
      files: [
        {
          key: 'uploads/a.txt',
          size: 20_000_000,
          lastModified: '2026-01-01T00:00:00.000Z',
          etag: '"abc"',
          contentType: 'text/plain',
        },
      ],
      prefixes: [],
      emptyPrefixes: [],
    })
  }) as typeof globalThis.fetch
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={['/buckets/photos?prefix=uploads/']}>
        <Routes>
          <Route path="/buckets/:bucket" element={<ObjectBrowserPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

test('hides write actions for a read-only prefix', async () => {
  const screen = renderBrowser({ putObject: false, deleteObject: false })
  expect(await screen.findByText('19.1 MiB')).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Upload' })).toBeNull()
  expect(screen.queryByRole('button', { name: 'New Folder' })).toBeNull()
  expect(screen.queryByRole('button', { name: 'Delete' })).toBeNull()
})

test('shows upload and delete when the prefix allows them', async () => {
  const screen = renderBrowser({ putObject: true, deleteObject: true })
  expect(await screen.findByRole('button', { name: 'Upload' })).toBeTruthy()
  expect(screen.getByRole('button', { name: 'New Folder' })).toBeTruthy()
  expect(screen.getByRole('button', { name: 'Delete' })).toBeTruthy()
})
