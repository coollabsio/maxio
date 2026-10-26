import { afterEach, expect, test } from 'bun:test'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, waitFor, within } from '@testing-library/react'
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

const previewListing = {
  files: [
    { key: 'readme.txt', size: 5, lastModified: '2026-01-02T03:04:05Z', etag: '"a"', contentType: 'text/plain' },
    { key: 'bundle.zip', size: 9, lastModified: '2026-01-02T03:04:05Z', etag: '"b"', contentType: 'application/zip' },
  ],
  prefixes: [],
  emptyPrefixes: [],
}

function renderPreviewBrowser(downloads: string[] = []) {
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = input instanceof Request ? input : new Request(input, init)
    const url = new URL(request.url)
    if (url.pathname.includes('/download/readme.txt')) {
      downloads.push(url.pathname)
      return new Response('hello', { status: 200, headers: { 'Content-Type': 'text/plain' } })
    }
    if (url.pathname.includes('/capabilities')) {
      return json({ createBucket: false, deleteBucket: false, putObject: false, deleteObject: false })
    }
    if (url.pathname.includes('/versioning')) return json({ enabled: false })
    return json(previewListing)
  }) as typeof globalThis.fetch
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={['/buckets/docs']}>
        <Routes>
          <Route path="/buckets/:bucket" element={<ObjectBrowserPage />} />
        </Routes>
      </MemoryRouter>
      <Toaster />
    </QueryClientProvider>,
  )
}

test('lists the content type and only offers preview for previewable files', async () => {
  const screen = renderPreviewBrowser()

  const readme = within((await screen.findByText('readme.txt')).closest('tr')!)
  expect(readme.getByText('text/plain')).toBeTruthy()
  expect(readme.getByRole('button', { name: 'Preview' })).toBeTruthy()

  const zip = within(screen.getByText('bundle.zip').closest('tr')!)
  expect(zip.getByText('application/zip')).toBeTruthy()
  expect(zip.queryByRole('button', { name: 'Preview' })).toBeNull()
})

test('preview opens a dialog with the fetched text and an in-page download', async () => {
  const user = userEvent.setup()
  const downloads: string[] = []
  const screen = renderPreviewBrowser(downloads)

  const readme = within((await screen.findByText('readme.txt')).closest('tr')!)
  await user.click(readme.getByRole('button', { name: 'Preview' }))

  const dialog = within(await screen.findByRole('dialog', { name: 'readme.txt' }))
  await waitFor(() => expect(dialog.getByText('hello')).toBeTruthy())
  expect(dialog.getByText('text/plain')).toBeTruthy()
  expect(downloads).toEqual(['/maxio/api/buckets/docs/download/readme.txt'])

  // Like the row action, the footer download fetches in place (errors stay in the page) instead of following a link.
  expect(dialog.queryByRole('link', { name: 'Download' })).toBeNull()
  // happy-dom would navigate the test window to the blob: URL the download helper clicks.
  const realClick = HTMLAnchorElement.prototype.click
  let saved: string | null = null
  HTMLAnchorElement.prototype.click = function (this: HTMLAnchorElement) {
    saved = this.download
  }
  try {
    await user.click(dialog.getByRole('button', { name: 'Download' }))
    await waitFor(() => expect(saved).toBe('readme.txt'))
  } finally {
    HTMLAnchorElement.prototype.click = realClick
  }
  expect(downloads).toHaveLength(2)

  await user.click(dialog.getByRole('button', { name: 'Close preview' }))
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
})

function renderServedAs(file: { key: string; contentType: string }, served: { body: string; contentType: string }) {
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = input instanceof Request ? input : new Request(input, init)
    const url = new URL(request.url)
    if (url.pathname.includes('/download/')) {
      return new Response(served.body, { status: 200, headers: { 'Content-Type': served.contentType } })
    }
    if (url.pathname.includes('/capabilities')) {
      return json({ createBucket: false, deleteBucket: false, putObject: false, deleteObject: false })
    }
    if (url.pathname.includes('/versioning')) return json({ enabled: false })
    return json({
      files: [{ ...file, size: served.body.length, lastModified: '2026-01-02T03:04:05Z', etag: '"a"' }],
      prefixes: [],
      emptyPrefixes: [],
    })
  }) as typeof globalThis.fetch
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
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

test('preview refuses to frame a file whose served type no longer matches the listing', async () => {
  const user = userEvent.setup()
  const screen = renderServedAs(
    { key: 'report.pdf', contentType: 'application/pdf' },
    { body: '<script>alert(1)</script>', contentType: 'text/html' },
  )

  await user.click(within((await screen.findByText('report.pdf')).closest('tr')!).getByRole('button', { name: 'Preview' }))
  const dialog = within(await screen.findByRole('dialog', { name: 'report.pdf' }))
  expect((await dialog.findByRole('alert')).textContent).toContain('changed since it was listed')
  expect(screen.baseElement.querySelector('iframe')).toBeNull()
})

test('SVG previews use a data: URL, never a same-origin blob: URL', async () => {
  const user = userEvent.setup()
  const screen = renderServedAs(
    { key: 'logo.svg', contentType: 'image/svg+xml' },
    { body: '<svg xmlns="http://www.w3.org/2000/svg"/>', contentType: 'image/svg+xml' },
  )

  await user.click(within((await screen.findByText('logo.svg')).closest('tr')!).getByRole('button', { name: 'Preview' }))
  const dialog = within(await screen.findByRole('dialog', { name: 'logo.svg' }))
  const img = await dialog.findByRole('img', { name: 'logo.svg' })
  expect(img.getAttribute('src')).toStartWith('data:image/svg+xml')
})
