import { afterEach, expect, test } from 'bun:test'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router'
import { Toaster } from '@/components/ui/sonner'
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

test('denied download stays on the page and shows the error', async () => {
  const userEvents = userEvent.setup()
  let sawDownload = false
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = input instanceof Request ? input : new Request(input, init)
    const url = new URL(request.url)
    if (url.pathname.includes('/download/')) {
      sawDownload = true
      return new Response(JSON.stringify({ error: 'Access Denied' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      })
    }
    if (url.pathname.includes('/capabilities')) {
      return json({ createBucket: false, deleteBucket: false, putObject: false, deleteObject: false })
    }
    if (url.pathname.includes('/versioning')) return json({ enabled: false })
    return json({
      files: [
        {
          key: 'secret.txt',
          size: 4,
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
  const screen = render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={['/buckets/photos']}>
        <Routes>
          <Route path="/buckets/:bucket" element={<ObjectBrowserPage />} />
        </Routes>
      </MemoryRouter>
      <Toaster />
    </QueryClientProvider>,
  )
  await userEvents.click(await screen.findByRole('button', { name: 'Download' }))
  expect(sawDownload).toBe(true)
  expect(screen.queryByRole('link', { name: 'Download' })).toBeNull()
  expect(await screen.findByText('Access Denied')).toBeTruthy()
  expect(screen.getByText('secret.txt')).toBeTruthy()
})

test('a 403 during upload shows a toast and leaves the browser in place', async () => {
  const userEvents = userEvent.setup()
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = input instanceof Request ? input : new Request(input, init)
    const url = new URL(request.url)
    if (url.pathname.includes('/upload/') && request.method === 'PUT') {
      return new Response(JSON.stringify({ error: 'Access Denied' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      })
    }
    if (url.pathname.includes('/capabilities')) {
      return json({ createBucket: false, deleteBucket: false, putObject: true, deleteObject: true })
    }
    if (url.pathname.includes('/versioning')) return json({ enabled: false })
    return json({ files: [], prefixes: [], emptyPrefixes: [] })
  }) as typeof globalThis.fetch
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const screen = render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={['/buckets/photos']}>
        <Routes>
          <Route path="/buckets/:bucket" element={<ObjectBrowserPage />} />
        </Routes>
      </MemoryRouter>
      <Toaster />
    </QueryClientProvider>,
  )
  const input = await screen.findByTestId('upload-input')
  await userEvents.upload(input, new File(['nope'], 'note.txt', { type: 'text/plain' }))
  expect((await screen.findAllByText('Access Denied')).length).toBeGreaterThan(0)
  expect(screen.getByRole('heading', { name: 'photos' })).toBeTruthy()
})
