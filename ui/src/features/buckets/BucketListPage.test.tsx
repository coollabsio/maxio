import { afterEach, expect, spyOn, test } from 'bun:test'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router'
import { BucketListPage } from './BucketListPage'

const realFetch = globalThis.fetch

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

afterEach(() => {
  globalThis.fetch = realFetch
})

test('create bucket dialog explains why the server rejects a name', async () => {
  const consoleError = spyOn(console, 'error').mockImplementation(() => {})
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const request = input as Request
    if (request.method === 'POST') return json(400, { error: 'Bucket name must be 3-63 characters long.' })
    return json(200, { buckets: [], createBucket: true })
  }) as typeof globalThis.fetch
  const user = userEvent.setup()
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  const screen = render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <BucketListPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )

  await user.click(await screen.findByRole('button', { name: 'Create Bucket' }))
  const dialog = within(await screen.findByRole('dialog', { name: 'Create bucket' }))
  expect(dialog.getByText(/3-63 characters: lowercase letters, numbers, hyphens/)).toBeTruthy()

  await user.type(dialog.getByLabelText('Bucket name'), 'ab')
  await user.click(dialog.getByRole('button', { name: 'Create bucket' }))

  await waitFor(() => expect(dialog.getByRole('alert').textContent).toContain('Bucket name must be 3-63 characters long.'))

  // Editing the name clears the old error.
  await user.type(dialog.getByLabelText('Bucket name'), 'c')
  expect(dialog.queryByRole('alert')).toBeNull()
  consoleError.mockRestore()
})

test('hides create and delete when the caller cannot write', async () => {
  globalThis.fetch = (async () =>
    json(200, {
      createBucket: false,
      buckets: [
        {
          name: 'photos',
          createdAt: '2026-01-01T00:00:00.000Z',
          versioning: false,
          encryption: false,
          publicRead: false,
          publicList: false,
          tagCount: 0,
          canDelete: false,
        },
      ],
    })) as unknown as typeof globalThis.fetch
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const screen = render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <BucketListPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )
  await screen.findByText('photos')
  expect(screen.queryByRole('button', { name: 'Create Bucket' })).toBeNull()
  expect(screen.queryByRole('button', { name: 'Delete bucket' })).toBeNull()
})
