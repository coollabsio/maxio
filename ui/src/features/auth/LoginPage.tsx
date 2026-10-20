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
    onSuccess: (data) => {
      queryClient.setQueryData(authKeys.check(), data)
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
    <div className="flex min-h-dvh w-full items-center justify-center bg-app bg-[radial-gradient(circle,rgb(0_0_0/0.1)_1px,transparent_1.3px)] bg-size-[20px_20px] px-6 py-8 dark:bg-[radial-gradient(circle,rgb(255_255_255/0.07)_1px,transparent_1.3px)]">
      <div className="mx-auto flex w-full max-w-sm flex-col gap-6 text-black dark:text-fg">
        <div className="flex flex-col items-center gap-3 text-center">
          <img src={`${import.meta.env.BASE_URL}logo.svg`} alt="" className="size-10" />
          <div className="flex flex-col gap-1">
            <h1>MaxIO</h1>
            <p className="text-[13px] text-neutral-500 dark:text-fg-faint">Sign in to the storage console</p>
          </div>
        </div>

        <form
          onSubmit={handleSubmit}
          className="flex flex-col gap-4 rounded-xl border border-neutral-200 bg-white p-6 shadow-[0_1px_2px_rgb(0_0_0/0.05)] dark:border-white/[0.08] dark:bg-panel"
        >
          <div className="flex flex-col gap-1.5">
            <label htmlFor="accessKey" className="text-[13px] font-medium text-neutral-600 dark:text-fg-dim">
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
            <label htmlFor="secretKey" className="text-[13px] font-medium text-neutral-600 dark:text-fg-dim">
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
                className="icon-button absolute top-1/2 right-0.5 -translate-y-1/2"
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
            className="mt-2 h-9 w-full justify-center px-4"
            disabled={loginMutation.isPending}
          >
            {loginMutation.isPending ? 'Signing in...' : 'Login'}
          </Button>
        </form>
      </div>
    </div>
  )
}
