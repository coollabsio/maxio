import { afterEach, expect, test } from 'bun:test'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router'
import { UserDetailPage } from './UserDetailPage'

const realFetch = globalThis.fetch

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

const user = {
  name: 'alice',
  userId: 'MXIUEXAMPLE',
  enabled: true,
  createdAt: '2026-01-01T00:00:00.000Z',
  keyCount: 1,
  attachedPolicies: ['readwrite'],
  inlinePolicies: [],
}

const existingKey = {
  accessKeyId: 'MXIAEXISTINGKEY0001',
  userName: 'alice',
  label: 'alice',
  status: 'Active',
  createdAt: '2026-01-01T00:00:00.000Z',
  hasPolicy: false,
}

afterEach(() => {
  globalThis.fetch = realFetch
})

function renderUser(onRequest: (request: Request) => Response | Promise<Response>) {
  const requests: Request[] = []
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = input instanceof Request ? input : new Request(input, init)
    requests.push(request)
    return onRequest(request)
  }) as typeof globalThis.fetch
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  const screen = render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={['/users/alice']}>
        <Routes>
          <Route path="/users/:name" element={<UserDetailPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
  return { screen, requests }
}

function route(request: Request, preview = '{"Version":"2012-10-17","Statement":[]}') {
  const url = new URL(request.url)
  if (url.pathname === '/api/iam/users/alice' && request.method === 'GET') return json(200, user)
  if (url.pathname === '/api/iam/users/alice/keys' && request.method === 'GET') return json(200, { keys: [existingKey] })
  if (url.pathname === '/api/iam/policies' && request.method === 'GET') return json(200, { policies: [] })
  if (url.pathname === '/api/iam/preview' && request.method === 'POST') return json(200, { documentJson: preview })
  return json(500, { error: `unexpected ${request.method} ${url.pathname}` })
}

test('creating a key stores a narrowing policy and does not grant the user', async () => {
  const userEvents = userEvent.setup()
  let created: unknown
  const { screen } = renderUser(async (request) => {
    const url = new URL(request.url)
    if (url.pathname === '/api/iam/users/alice/keys' && request.method === 'POST') {
      created = await request.json()
      return json(200, {
        accessKeyId: 'MXIANEWKEY000000001',
        secretAccessKey: 'mxsk_example',
        createdAt: '2026-01-02T00:00:00.000Z',
        status: 'Active',
      })
    }
    return route(request, '{"Version":"2012-10-17","Statement":[{"Resource":"arn:aws:s3:::photos/uploads/*"}]}')
  })

  await userEvents.click(await screen.findByRole('button', { name: 'Create access key' }))
  const dialog = within(await screen.findByRole('dialog', { name: 'Create access key' }))
  expect(dialog.queryByRole('checkbox')).toBeNull()
  expect(dialog.getByText(/limits only this key/)).toBeTruthy()
  expect(dialog.getByText(/does not grant the user/)).toBeTruthy()

  await userEvents.type(dialog.getByLabelText('Buckets'), 'photos')
  await userEvents.type(dialog.getByLabelText('Prefix'), 'uploads/')
  await screen.findByDisplayValue(/photos\/uploads\/\*/)
  await userEvents.click(dialog.getByRole('button', { name: 'Create key' }))

  await waitFor(() => expect(created).toBeTruthy())
  expect(created).toMatchObject({ buckets: ['photos'], prefix: 'uploads/', access: 'read', keyOnly: true })
  expect(screen.queryByRole('dialog', { name: 'Grant scope to user' })).toBeNull()
})

test('shows a key policy and does not claim the user has no policies', async () => {
  const { screen } = renderUser((request) => {
    const url = new URL(request.url)
    if (url.pathname === '/api/iam/users/alice' && request.method === 'GET') {
      return json(200, { ...user, attachedPolicies: [], inlinePolicies: [] })
    }
    if (url.pathname === '/api/iam/users/alice/keys' && request.method === 'GET') {
      return json(200, {
        keys: [
          {
            ...existingKey,
            hasPolicy: true,
            policySummary: 'Key policy: arn:aws:s3:::photos/uploads/*',
          },
        ],
      })
    }
    return route(request)
  })
  expect(await screen.findByText('Key policy: arn:aws:s3:::photos/uploads/*')).toBeTruthy()
  expect(screen.getByText(/Limits this key only/)).toBeTruthy()
  expect(screen.queryByText(/This user has no policies/)).toBeNull()
})

test('deleting an access key asks for confirmation', async () => {
  const userEvents = userEvent.setup()
  let deleted = false
  const { screen } = renderUser((request) => {
    const url = new URL(request.url)
    if (url.pathname.startsWith('/api/iam/users/alice/keys/') && request.method === 'DELETE') {
      deleted = true
      return json(200, { ok: true })
    }
    return route(request)
  })
  await userEvents.click(await screen.findByRole('button', { name: 'Delete' }))
  expect(deleted).toBe(false)
  const dialog = within(await screen.findByRole('dialog', { name: 'Delete access key?' }))
  await userEvents.click(dialog.getByRole('button', { name: 'Delete key' }))
  await waitFor(() => expect(deleted).toBe(true))
})

test('granting a scope is a separate action from creating a key', async () => {
  const userEvents = userEvent.setup()
  const posts: { path: string; body: unknown }[] = []
  const { screen } = renderUser(async (request) => {
    const url = new URL(request.url)
    if (request.method === 'POST' || request.method === 'PUT') {
      posts.push({ path: url.pathname, body: await request.json() })
    }
    if (url.pathname.startsWith('/api/iam/users/alice/inline/') && request.method === 'PUT') {
      return json(200, { ok: true })
    }
    return route(request, '{"Version":"2012-10-17","Statement":[{"Effect":"Allow"}]}')
  })

  await userEvents.click(await screen.findByRole('button', { name: 'Grant scope to user' }))
  const dialog = within(await screen.findByRole('dialog', { name: 'Grant scope to user' }))
  expect(dialog.getByText(/does not create an access key/)).toBeTruthy()
  expect(dialog.queryByRole('checkbox')).toBeNull()
  await userEvents.type(dialog.getByLabelText('Buckets'), 'photos')
  await userEvents.selectOptions(dialog.getByLabelText('Access'), 'read')
  await screen.findByDisplayValue(/Allow/)
  await userEvents.click(dialog.getByRole('button', { name: 'Grant scope' }))

  await waitFor(() => expect(posts.some((post) => post.path.includes('/inline/'))).toBe(true))
  const grant = posts.find((post) => post.path.includes('/inline/'))
  expect(grant?.path).toBe('/api/iam/users/alice/inline/grant-photos-read')
  expect(grant?.body).toMatchObject({ documentJson: expect.stringContaining('Allow') })
  expect(posts.some((post) => post.path.endsWith('/keys'))).toBe(false)
})
