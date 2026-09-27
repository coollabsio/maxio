import { useQuery } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { Navigate, useLocation } from 'react-router'
import { authKeys } from '@/api/queryKeys'
import { checkAuth } from './api'

/** Renders `children` for a valid console session, otherwise redirects to `/login` (remembering the location). */
export function RequireAuth({ children }: { children: ReactNode }) {
  const location = useLocation()
  const authQuery = useQuery({ queryKey: authKeys.check(), queryFn: checkAuth, retry: false })

  if (authQuery.isPending) return null
  if (!authQuery.isSuccess) {
    return <Navigate to="/login" replace state={{ from: `${location.pathname}${location.search}` }} />
  }
  return children
}
