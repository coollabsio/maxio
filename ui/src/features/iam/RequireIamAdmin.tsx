import { useQuery } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { authKeys } from '@/api/queryKeys'
import { Callout } from '@/components/ui/callout'
import { PageHeader } from '@/components/ui/page-header'
import { checkAuth } from '@/features/auth/api'

/** Admin-only pages. Non-admins never see the admin actions or a loading list. */
export function RequireIamAdmin({ children }: { children: ReactNode }) {
  const session = useQuery({ queryKey: authKeys.check(), queryFn: checkAuth, retry: false })
  if (session.isPending) return null
  if (session.data?.iamAdmin !== true) {
    return (
      <div className="flex flex-col gap-6">
        <PageHeader title="Admins only" description="This page is for IAM administrators." />
        <Callout type="warning">You do not have permission to manage users or policies.</Callout>
      </div>
    )
  }
  return children
}
