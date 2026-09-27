import { ArrowLeft, ChevronRight, Menu } from 'lucide-react'
import { Fragment } from 'react'
import { useMatch, useNavigate, useSearchParams } from 'react-router'
import { bucketPath, buildBreadcrumbs, normalizePrefix, parentPrefix } from '@/lib/paths'
import { DESKTOP_QUERY, useMediaQuery } from '@/lib/useMediaQuery'

const linkClass =
  'shrink-0 rounded-sm text-neutral-600 transition-colors hover:text-coollabs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-coollabs dark:text-neutral-400 dark:hover:text-warning dark:focus-visible:ring-warning'

function Separator() {
  return (
    <li className="inline-flex items-center gap-1.5 text-neutral-400" aria-hidden="true">
      <ChevronRight className="size-3 shrink-0" />
    </li>
  )
}

function Current({ children }: { children: string }) {
  return (
    <li className="inline-flex items-center gap-1.5">
      <span className="shrink-0 text-black dark:text-white" aria-current="page">
        {children}
      </span>
    </li>
  )
}

/** Top bar of the shell: page title on the bucket list, back button + breadcrumbs inside a bucket. */
export function Header({ menuOpen, onOpenMenu }: { menuOpen: boolean; onOpenMenu: () => void }) {
  const navigate = useNavigate()
  const isDesktop = useMediaQuery(DESKTOP_QUERY)
  const [searchParams] = useSearchParams()
  const settingsMatch = useMatch('/buckets/:bucket/settings')
  const objectsMatch = useMatch('/buckets/:bucket')
  const bucket = settingsMatch?.params.bucket ?? objectsMatch?.params.bucket ?? null
  const isSettings = settingsMatch !== null
  const prefix = normalizePrefix(searchParams.get('prefix'))
  const crumbs = bucket ? buildBreadcrumbs(bucket, prefix) : []

  function goBack() {
    if (!bucket || isSettings) {
      navigate('/')
      return
    }
    const parent = parentPrefix(prefix)
    navigate(parent === null ? '/' : bucketPath(bucket, parent))
  }

  return (
    <div className="flex h-14 shrink-0 items-center gap-2 px-4 md:px-6">
      {isDesktop ? null : (
        <button
          type="button"
          onClick={onOpenMenu}
          className="-ml-1 shrink-0 rounded-sm p-1 text-neutral-600 transition-colors hover:text-coollabs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-coollabs dark:text-neutral-400 dark:hover:text-warning dark:focus-visible:ring-warning"
          aria-label="Open menu"
          aria-expanded={menuOpen}
        >
          <Menu className="size-5" />
        </button>
      )}
      {bucket ? (
        <>
          <button
            type="button"
            onClick={goBack}
            className="shrink-0 rounded-sm p-1 text-neutral-600 transition-colors hover:text-coollabs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-coollabs dark:text-neutral-400 dark:hover:text-warning dark:focus-visible:ring-warning"
            aria-label={isSettings ? 'Back to buckets' : 'Go up one folder'}
          >
            <ArrowLeft className="size-4" />
          </button>
          <nav aria-label="Breadcrumb" className="min-w-0 overflow-x-auto">
            <ol className="flex flex-wrap items-center gap-1.5 text-sm font-medium">
              <li className="inline-flex items-center gap-1.5">
                <button type="button" className={linkClass} onClick={() => navigate('/')}>
                  Buckets
                </button>
              </li>
              <Separator />
              {isSettings ? (
                <>
                  <li className="inline-flex items-center gap-1.5">
                    <button type="button" className={linkClass} onClick={() => navigate(bucketPath(bucket))}>
                      {bucket}
                    </button>
                  </li>
                  <Separator />
                  <Current>Settings</Current>
                </>
              ) : crumbs.length > 1 ? (
                crumbs.map((crumb, index) =>
                  index < crumbs.length - 1 ? (
                    <Fragment key={crumb.prefix}>
                      <li className="inline-flex items-center gap-1.5">
                        <button type="button" className={linkClass} onClick={() => navigate(bucketPath(bucket, crumb.prefix))}>
                          {crumb.label}
                        </button>
                      </li>
                      <Separator />
                    </Fragment>
                  ) : (
                    <Current key={crumb.prefix}>{crumb.label}</Current>
                  ),
                )
              ) : (
                <Current>{bucket}</Current>
              )}
            </ol>
          </nav>
        </>
      ) : (
        <h2 className="text-lg font-semibold">Buckets</h2>
      )}
    </div>
  )
}
