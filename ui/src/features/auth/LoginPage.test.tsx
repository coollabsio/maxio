import { afterEach, expect, spyOn, test } from 'bun:test'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router'
import { LoginPage } from './LoginPage'

const realFetch = globalThis.fetch
let requests: Request[] = []

function renderLogin(respond: () => Response) {
  requests = []
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    requests.push(input as Request)
    return respond()
  }) as typeof globalThis.fetch
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={['/login']}>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/" element={<p>Bucket list</p>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

afterEach(() => {
  globalThis.fetch = realFetch
})

test('renders the login form', () => {
  const screen = renderLogin(() => new Response(null, { status: 500 }))
  expect(screen.getByRole('heading', { name: 'MaxIO' })).toBeTruthy()
  expect(screen.getByLabelText(/Access Key/)).toBeTruthy()
  expect(screen.getByLabelText(/Secret Key/)).toBeTruthy()
  expect(screen.getByRole('button', { name: 'Login' })).toBeTruthy()
})

test('submits the credentials and navigates to the bucket list', async () => {
  const user = userEvent.setup()
  const screen = renderLogin(() => new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } }))

  await user.type(screen.getByLabelText(/Access Key/), 'maxioadmin')
  await user.type(screen.getByLabelText(/Secret Key/), 'secret')
  await user.click(screen.getByRole('button', { name: 'Login' }))

  await screen.findByText('Bucket list')
  expect(new URL(requests[0].url).pathname).toBe('/api/auth/login')
  expect(await requests[0].json()).toEqual({ accessKey: 'maxioadmin', secretKey: 'secret' })
})

test('shows the server error message', async () => {
  const consoleError = spyOn(console, 'error').mockImplementation(() => {})
  const user = userEvent.setup()
  const screen = renderLogin(
    () =>
      new Response(JSON.stringify({ error: 'Invalid credentials' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      }),
  )

  await user.type(screen.getByLabelText(/Access Key/), 'maxioadmin')
  await user.type(screen.getByLabelText(/Secret Key/), 'wrong')
  await user.click(screen.getByRole('button', { name: 'Login' }))

  await waitFor(() => expect(screen.getByText('Invalid credentials')).toBeTruthy())
  expect(screen.queryByText('Bucket list')).toBeNull()
  expect(consoleError).toHaveBeenCalled()
  consoleError.mockRestore()
})

test('toggles the secret key visibility', async () => {
  const user = userEvent.setup()
  const screen = renderLogin(() => new Response(null, { status: 500 }))
  const secret = screen.getByLabelText(/Secret Key/) as HTMLInputElement
  expect(secret.type).toBe('password')
  await user.click(screen.getByRole('button', { name: 'Show secret key' }))
  expect(secret.type).toBe('text')
})
