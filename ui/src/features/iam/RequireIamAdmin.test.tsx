import { expect, test } from 'bun:test'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { authKeys } from '@/api/queryKeys'
import { RequireIamAdmin } from './RequireIamAdmin'

function renderGuard(iamAdmin: boolean) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  queryClient.setQueryData(authKeys.check(), {
    ok: true,
    root: false,
    iamAdmin,
    kind: 'user',
    userName: 'photos-readonly',
    label: null,
    accessKeyId: 'MXIA',
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <RequireIamAdmin>
          <button type="button">Create user</button>
        </RequireIamAdmin>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

test('non-admins see an admins-only message and no admin actions', () => {
  const screen = renderGuard(false)
  expect(screen.getByRole('heading', { name: 'Admins only' })).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Create user' })).toBeNull()
})

test('admins see the page', () => {
  const screen = renderGuard(true)
  expect(screen.getByRole('button', { name: 'Create user' })).toBeTruthy()
  expect(screen.queryByRole('heading', { name: 'Admins only' })).toBeNull()
})
