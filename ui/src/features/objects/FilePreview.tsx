import { Download } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Button } from '@/components/ui/button'
import { Dialog } from '@/components/ui/dialog'
import { displayName, downloadUrl } from '@/lib/paths'
import { BINARY_PREVIEW_CAP, TEXT_PREVIEW_CAP, previewKind } from '@/lib/preview'

interface FilePreviewProps {
  bucket: string
  objectKey: string
  contentType: string
  size: number
  onClose: () => void
}

type LoadState =
  | { status: 'loading' }
  | { status: 'error'; message: string }
  | { status: 'text'; text: string; truncated: boolean }
  | { status: 'blob'; url: string }

const muted = 'text-sm text-neutral-600 dark:text-neutral-400'

/**
 * Modal preview of one object: images and PDFs through a blob URL, text inline (capped), everything else
 * (including HTML, which is never rendered in the console's same-origin session) falls back to a download link.
 */
export function FilePreview({ bucket, objectKey, contentType, size, onClose }: FilePreviewProps) {
  const kind = previewKind(contentType)
  const name = displayName(objectKey)
  const url = downloadUrl(bucket, objectKey)
  const tooLarge = size > BINARY_PREVIEW_CAP
  const skipped = kind === 'unsupported' || tooLarge
  const [state, setState] = useState<LoadState>({ status: 'loading' })

  // Keep text selection inside the preview instead of bleeding into the page behind the modal.
  useEffect(() => {
    document.body.classList.add('preview-open')
    return () => document.body.classList.remove('preview-open')
  }, [])

  useEffect(() => {
    if (skipped) return
    const controller = new AbortController()
    let blobUrl: string | null = null

    async function load() {
      try {
        const res = await fetch(url, { credentials: 'same-origin', signal: controller.signal })
        if (!res.ok) throw new Error(`Request failed (${res.status})`)
        if (kind === 'text') {
          const full = await res.text()
          const truncated = full.length > TEXT_PREVIEW_CAP
          if (!controller.signal.aborted) {
            setState({ status: 'text', text: truncated ? full.slice(0, TEXT_PREVIEW_CAP) : full, truncated })
          }
        } else {
          const blob = await res.blob()
          if (controller.signal.aborted) return
          blobUrl = URL.createObjectURL(blob)
          setState({ status: 'blob', url: blobUrl })
        }
      } catch (err) {
        if (controller.signal.aborted) return
        console.error('FilePreview load failed:', err)
        setState({ status: 'error', message: err instanceof Error ? err.message : 'Failed to load preview' })
      }
    }

    void load()
    return () => {
      controller.abort()
      if (blobUrl) URL.revokeObjectURL(blobUrl)
    }
  }, [url, kind, skipped])

  let body: React.ReactNode
  if (kind === 'unsupported') {
    body = <p className={muted}>No preview available for this file type.</p>
  } else if (tooLarge) {
    body = <p className={muted}>File is too large to preview. Download it to view.</p>
  } else if (state.status === 'loading') {
    body = <p className={muted}>Loading preview…</p>
  } else if (state.status === 'error') {
    body = (
      <p role="alert" className="text-sm text-red-600 dark:text-red-400">
        {state.message}
      </p>
    )
  } else if (state.status === 'blob' && kind === 'image') {
    body = <img src={state.url} alt={name} className="mx-auto max-h-[70vh] max-w-full object-contain" />
  } else if (state.status === 'blob' && kind === 'pdf') {
    body = <iframe src={state.url} title={name} className="h-[70vh] w-full border-0" />
  } else if (state.status === 'text') {
    body = (
      <>
        {state.truncated ? (
          <p className="mb-2 text-xs text-amber-600 dark:text-amber-400">
            Preview truncated to the first {Math.round(TEXT_PREVIEW_CAP / 1024)} KB.
          </p>
        ) : null}
        <pre className="select-text overflow-auto whitespace-pre-wrap break-words rounded-sm bg-neutral-50 p-3 font-mono text-xs text-neutral-800 dark:bg-coolgray-200 dark:text-neutral-200">
          {state.text}
        </pre>
      </>
    )
  }

  return (
    <Dialog
      open
      size="lg"
      title={name}
      description={contentType || 'unknown type'}
      closeLabel="Close preview"
      onClose={onClose}
      footer={
        // The server sends `Content-Disposition: attachment`, so a plain link downloads without a popup.
        <Button render={<a href={url} />} nativeButton={false} variant="default">
          <Download className="size-4 mr-1" /> Download
        </Button>
      }
    >
      {body}
    </Dialog>
  )
}
