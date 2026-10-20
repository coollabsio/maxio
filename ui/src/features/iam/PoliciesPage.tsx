import { useQuery } from '@tanstack/react-query'
import { Plus, ScrollText } from 'lucide-react'
import { useNavigate } from 'react-router'
import { ApiError } from '@/api/client'
import { iamKeys } from '@/api/queryKeys'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Callout } from '@/components/ui/callout'
import { PageHeader } from '@/components/ui/page-header'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { listIamPolicies } from './api'

export function PoliciesPage() {
  const navigate = useNavigate()
  const policiesQuery = useQuery({ queryKey: iamKeys.policies(), queryFn: listIamPolicies })
  const policies = policiesQuery.data?.policies ?? []

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Policies"
        description="Built-in policies and custom JSON documents. Attach them to users from the user page."
        actions={
          <Button variant="highlighted" onClick={() => navigate('/policies/new')}>
            <Plus /> Create policy
          </Button>
        }
      />
      {policiesQuery.isError ? (
        <Callout type="danger">
          {policiesQuery.error instanceof ApiError ? policiesQuery.error.message : 'Failed to load policies'}
        </Callout>
      ) : policiesQuery.isPending ? (
        <p className="text-sm text-muted-foreground">Loading...</p>
      ) : policies.length === 0 ? (
        <Callout type="info">
          <span className="inline-flex items-center gap-2">
            <ScrollText className="size-4 opacity-70" />
            No policies.
          </span>
        </Callout>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>Description</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {policies.map((policy) => (
              <TableRow key={policy.name} className="cursor-pointer" onClick={() => navigate(`/policies/${policy.name}`)}>
                <TableCell className="font-medium">{policy.name}</TableCell>
                <TableCell>
                  <Badge variant={policy.builtin ? 'warning' : 'success'} label={policy.builtin ? 'Built-in' : 'Custom'} />
                </TableCell>
                <TableCell className="text-neutral-600 dark:text-fg-dim">{policy.description}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </div>
  )
}
