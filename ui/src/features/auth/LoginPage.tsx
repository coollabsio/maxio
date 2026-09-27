import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Eye, EyeOff } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { useLocation, useNavigate } from 'react-router'
import { ApiError } from '@/api/client'
import { authKeys } from '@/api/queryKeys'
import { Button } from '@/components/ui/button'
import { Callout } from '@/components/ui/callout'
import { Highlighted } from '@/components/ui/highlighted'
import { Input } from '@/components/ui/input'
import { login } from './api'

// `just dev` runs the server with the default credentials, so prefill them in the Vite dev build only.
const initialCredential = import.meta.env.DEV ? 'maxioadmin' : ''

function redirectTarget(state: unknown): string {
  const from = (state as { from?: unknown } | null)?.from
  return typeof from === 'string' && from.startsWith('/') && from !== '/login' ? from : '/'
}

export function LoginPage() {
  const navigate = useNavigate()
  const location = useLocation()
  const queryClient = useQueryClient()
  const [accessKey, setAccessKey] = useState(initialCredential)
  const [secretKey, setSecretKey] = useState(initialCredential)
  const [error, setError] = useState('')
  const [showSecret, setShowSecret] = useState(false)

  const loginMutation = useMutation({
    mutationFn: login,
    onSuccess: () => {
      queryClient.setQueryData(authKeys.check(), { ok: true })
      navigate(redirectTarget(location.state), { replace: true })
    },
  })

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError('')
    try {
      await loginMutation.mutateAsync({ accessKey, secretKey })
    } catch (err) {
      console.error('Login failed:', err)
      setError(err instanceof ApiError ? err.message : 'Connection failed')
    }
  }

  return (
    <div className="flex min-h-screen w-full items-center justify-center bg-gray-50 px-6 py-8 dark:bg-base">
      <div className="mx-auto w-full max-w-md space-y-8 text-black dark:text-white">
        <h1 className="text-center text-5xl font-extrabold tracking-tight text-gray-900 dark:text-white">MaxIO</h1>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <div className="flex flex-col gap-1.5">
            <label htmlFor="accessKey" className="text-sm text-muted-foreground">
              Access Key <Highlighted>*</Highlighted>
            </label>
            <Input
              id="accessKey"
              type="text"
              value={accessKey}
              onChange={(event) => setAccessKey(event.target.value)}
              autoComplete="username"
              required
            />
          </div>

          <div className="flex flex-col gap-1.5">
            <label htmlFor="secretKey" className="text-sm text-muted-foreground">
              Secret Key <Highlighted>*</Highlighted>
            </label>
            <div className="relative">
              <Input
                id="secretKey"
                type={showSecret ? 'text' : 'password'}
                value={secretKey}
                onChange={(event) => setSecretKey(event.target.value)}
                autoComplete="current-password"
                className="pr-10"
                required
              />
              <button
                type="button"
                onClick={() => setShowSecret((shown) => !shown)}
                className="absolute right-2 top-1/2 -translate-y-1/2 p-1 text-muted-foreground transition-colors hover:text-foreground"
                aria-label={showSecret ? 'Hide secret key' : 'Show secret key'}
              >
                {showSecret ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
              </button>
            </div>
          </div>

          {error ? <Callout type="danger">{error}</Callout> : null}

          <Button
            type="submit"
            variant="highlighted"
            className="mt-2 h-12 w-full justify-center px-4"
            disabled={loginMutation.isPending}
          >
            {loginMutation.isPending ? 'Signing in...' : 'Login'}
          </Button>
        </form>
      </div>
    </div>
  )
}
