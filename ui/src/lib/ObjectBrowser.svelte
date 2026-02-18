<script lang="ts">
  import { onMount } from 'svelte'
  import * as Table from '$lib/components/ui/table'
  import { Button } from '$lib/components/ui/button'
  import Folder from 'lucide-svelte/icons/folder'
  import FileIcon from 'lucide-svelte/icons/file'
  import Download from 'lucide-svelte/icons/download'
  import Upload from 'lucide-svelte/icons/upload'
  import Trash2 from 'lucide-svelte/icons/trash-2'
  import Share2 from 'lucide-svelte/icons/share-2'
  import Check from 'lucide-svelte/icons/check'
  import FolderPlus from 'lucide-svelte/icons/folder-plus'

  interface Props {
    bucket: string
    onBack: () => void
    onPrefixChange?: (prefix: string, breadcrumbs: { label: string; prefix: string }[]) => void
  }
  let { bucket, onBack, onPrefixChange }: Props = $props()

  interface S3File {
    key: string
    size: number
    lastModified: string
    etag: string
  }

  let prefix = $state('')
  let files = $state<S3File[]>([])
  let prefixes = $state<string[]>([])
  let emptyPrefixes = $state<Set<string>>(new Set())
  let loading = $state(true)
  let error = $state<string | null>(null)
  let uploading = $state(false)
  let fileInput: HTMLInputElement | undefined = $state()
  let copiedKey = $state<string | null>(null)
  let shareMenuKey = $state<string | null>(null)
  let showCreateFolder = $state(false)
  let newFolderName = $state('')
  let creatingFolder = $state(false)
  let shareMenuPos = $state({ top: 0, left: 0 })

  const expiryOptions = [
    { label: '1 hour', seconds: 3600 },
    { label: '6 hours', seconds: 21600 },
    { label: '24 hours', seconds: 86400 },
    { label: '7 days', seconds: 604800 },
  ]

  async function fetchObjects() {
    loading = true
    error = null
    try {
      const params = new URLSearchParams({ prefix, delimiter: '/' })
      const res = await fetch(`/api/buckets/${encodeURIComponent(bucket)}/objects?${params}`)
      if (res.ok) {
        const data = await res.json()
        files = data.files
        prefixes = data.prefixes
        emptyPrefixes = new Set(data.emptyPrefixes || [])
      } else {
        error = `Failed to load objects (${res.status})`
      }
    } catch (err) {
      console.error('fetchObjects failed:', err)
      error = 'Failed to connect to server'
    } finally {
      loading = false
    }
  }

  function notifyPrefix() {
    onPrefixChange?.(prefix, breadcrumbs)
  }

  export function navigateTo(newPrefix: string) {
    prefix = newPrefix
    fetchObjects()
    notifyPrefix()
  }

  export function goUp() {
    if (!prefix) {
      onBack()
      return
    }
    const trimmed = prefix.slice(0, -1)
    const lastSlash = trimmed.lastIndexOf('/')
    prefix = lastSlash >= 0 ? trimmed.slice(0, lastSlash + 1) : ''
    fetchObjects()
    notifyPrefix()
  }

  function displayName(fullPath: string): string {
    const trimmed = fullPath.endsWith('/') ? fullPath.slice(0, -1) : fullPath
    const lastSlash = trimmed.lastIndexOf('/')
    return lastSlash >= 0 ? trimmed.slice(lastSlash + 1) : trimmed
  }

  function formatSize(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`
  }

  function formatDate(iso: string): string {
    try {
      return new Date(iso).toLocaleString()
    } catch {
      return iso
    }
  }

  let breadcrumbs = $derived.by(() => {
    const parts = prefix.split('/').filter(Boolean)
    const crumbs: { label: string; prefix: string }[] = [
      { label: bucket, prefix: '' },
    ]
    let acc = ''
    for (const part of parts) {
      acc += part + '/'
      crumbs.push({ label: part, prefix: acc })
    }
    return crumbs
  })

  function downloadUrl(key: string): string {
    return `/api/buckets/${encodeURIComponent(bucket)}/download/${key}`
  }

  async function handleUpload() {
    const inputFiles = fileInput?.files
    if (!inputFiles || inputFiles.length === 0) return
    uploading = true
    error = null
    try {
      for (const file of inputFiles) {
        const key = `${prefix}${file.name}`
        const res = await fetch(`/api/buckets/${encodeURIComponent(bucket)}/upload/${key}`, {
          method: 'PUT',
          headers: { 'Content-Type': file.type || 'application/octet-stream' },
          body: file,
        })
        if (!res.ok) {
          const data = await res.json()
          error = data.error || `Failed to upload ${file.name}`
          break
        }
      }
      if (fileInput) fileInput.value = ''
      await fetchObjects()
    } catch (err) {
      console.error('Upload failed:', err)
      error = 'Failed to upload file'
    } finally {
      uploading = false
    }
  }

  async function deleteObject(key: string, e: Event) {
    e.stopPropagation()
    if (!confirm(`Delete "${displayName(key)}"?`)) return
    error = null
    try {
      const res = await fetch(`/api/buckets/${encodeURIComponent(bucket)}/objects/${key}`, { method: 'DELETE' })
      if (res.ok) {
        await fetchObjects()
      } else {
        const data = await res.json()
        error = data.error || `Failed to delete object`
      }
    } catch (err) {
      console.error('deleteObject failed:', err)
      error = 'Failed to connect to server'
    }
  }

  function toggleShareMenu(key: string, e: MouseEvent) {
    e.stopPropagation()
    if (shareMenuKey === key) {
      shareMenuKey = null
      return
    }
    const btn = e.currentTarget as HTMLElement
    const rect = btn.getBoundingClientRect()
    shareMenuPos = { top: rect.top, left: rect.right }
    shareMenuKey = key
  }

  async function shareObject(key: string, expires: number) {
    shareMenuKey = null
    error = null
    try {
      const res = await fetch(`/api/buckets/${encodeURIComponent(bucket)}/presign/${key}?expires=${expires}`)
      if (!res.ok) {
        const data = await res.json()
        console.error('Presign failed:', res.status, data)
        error = data.error || 'Failed to generate share link'
        return
      }
      const data = await res.json()
      await navigator.clipboard.writeText(data.url)
      copiedKey = key
      setTimeout(() => { copiedKey = null }, 2000)
    } catch (err) {
      console.error('shareObject failed:', err)
      error = 'Failed to generate share link'
    }
  }

  async function createFolder() {
    const name = newFolderName.trim()
    if (!name) return
    creatingFolder = true
    error = null
    try {
      const fullName = `${prefix}${name}`
      const res = await fetch(`/api/buckets/${encodeURIComponent(bucket)}/folders`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: fullName }),
      })
      if (res.ok) {
        newFolderName = ''
        showCreateFolder = false
        await fetchObjects()
      } else {
        const data = await res.json()
        error = data.error || 'Failed to create folder'
      }
    } catch (err) {
      console.error('createFolder failed:', err)
      error = 'Failed to create folder'
    } finally {
      creatingFolder = false
    }
  }

  async function deleteFolder(folderPrefix: string, e: Event) {
    e.stopPropagation()
    if (!confirm(`Delete empty folder "${displayName(folderPrefix)}"?`)) return
    error = null
    try {
      const res = await fetch(`/api/buckets/${encodeURIComponent(bucket)}/objects/${folderPrefix}`, { method: 'DELETE' })
      if (res.ok) {
        await fetchObjects()
      } else {
        const data = await res.json()
        error = data.error || 'Failed to delete folder'
      }
    } catch (err) {
      console.error('deleteFolder failed:', err)
      error = 'Failed to delete folder'
    }
  }

  function handleClickOutside(e: MouseEvent) {
    if (shareMenuKey) shareMenuKey = null
  }

  onMount(() => {
    fetchObjects()
    document.addEventListener('click', handleClickOutside)
    return () => document.removeEventListener('click', handleClickOutside)
  })
</script>

<div class="flex flex-col gap-4">
  {#if error}
    <div class="rounded-sm border border-destructive/50 bg-destructive/10 px-4 py-2 text-sm text-destructive">
      {error}
    </div>
  {/if}

  <div class="flex items-center gap-2">
    <input
      bind:this={fileInput}
      type="file"
      multiple
      class="hidden"
      onchange={handleUpload}
    />
    <Button variant="brand" class="h-8" onclick={() => fileInput?.click()} disabled={uploading}>
      <Upload class="size-4 mr-1" /> {uploading ? 'Uploading...' : 'Upload'}
    </Button>
    {#if showCreateFolder}
      <form onsubmit={(e) => { e.preventDefault(); createFolder() }} class="flex items-center gap-2">
        <input
          type="text"
          bind:value={newFolderName}
          placeholder="folder-name"
          class="input-cool h-8 w-40"
          disabled={creatingFolder}
        />
        <Button type="submit" variant="brand" class="h-8" disabled={creatingFolder || !newFolderName.trim()}>
          {creatingFolder ? 'Creating...' : 'Create'}
        </Button>
        <Button type="button" variant="ghost" class="h-8" onclick={() => { showCreateFolder = false; newFolderName = '' }}>
          Cancel
        </Button>
      </form>
    {:else}
      <Button variant="outline" class="h-8" onclick={() => (showCreateFolder = true)}>
        <FolderPlus class="size-4 mr-1" /> New Folder
      </Button>
    {/if}
  </div>

  {#if loading && files.length === 0 && prefixes.length === 0}
    <p class="text-sm text-muted-foreground">Loading...</p>
  {:else if files.length === 0 && prefixes.length === 0 && !error}
    <div class="flex flex-col items-center gap-2 py-12 text-muted-foreground">
      <Folder class="size-10 opacity-30" />
      <p class="text-sm">Empty</p>
    </div>
  {:else}
    <Table.Root>
      <Table.Header>
        <Table.Row>
          <Table.Head>Name</Table.Head>
          <Table.Head class="w-28 text-right">Size</Table.Head>
          <Table.Head class="w-48">Modified</Table.Head>
          <Table.Head class="w-24"></Table.Head>
        </Table.Row>
      </Table.Header>
      <Table.Body>
        {#each prefixes as p}
          <Table.Row class="cursor-pointer" onclick={() => navigateTo(p)}>
            <Table.Cell>
              <span class="flex items-center gap-2">
                <Folder class="size-4 shrink-0 text-muted-foreground" />
                <span class="font-medium">{displayName(p)}/</span>
              </span>
            </Table.Cell>
            <Table.Cell class="text-right text-muted-foreground">&mdash;</Table.Cell>
            <Table.Cell class="text-muted-foreground">&mdash;</Table.Cell>
            <Table.Cell>
              {#if emptyPrefixes.has(p)}
                <button
                  class="text-muted-foreground hover:text-destructive transition-colors"
                  onclick={(e) => deleteFolder(p, e)}
                  title="Delete empty folder"
                >
                  <Trash2 class="size-4" />
                </button>
              {/if}
            </Table.Cell>
          </Table.Row>
        {/each}
        {#each files as file}
          <Table.Row>
            <Table.Cell>
              <span class="flex items-center gap-2">
                <FileIcon class="size-4 shrink-0 text-muted-foreground" />
                <span class="font-medium">{displayName(file.key)}</span>
              </span>
            </Table.Cell>
            <Table.Cell class="text-right text-muted-foreground">{formatSize(file.size)}</Table.Cell>
            <Table.Cell class="text-muted-foreground">{formatDate(file.lastModified)}</Table.Cell>
            <Table.Cell class="w-24">
              <span class="flex items-center gap-3">
                <button
                  class="text-muted-foreground hover:text-foreground transition-colors"
                  onclick={(e) => toggleShareMenu(file.key, e)}
                  title="Copy presigned URL"
                >
                  {#if copiedKey === file.key}
                    <Check class="size-4 text-green-500" />
                  {:else}
                    <Share2 class="size-4" />
                  {/if}
                </button>
                <a href={downloadUrl(file.key)} class="text-muted-foreground hover:text-foreground" onclick={(e) => e.stopPropagation()} title="Download">
                  <Download class="size-4" />
                </a>
                <button
                  class="text-muted-foreground hover:text-destructive transition-colors"
                  onclick={(e) => deleteObject(file.key, e)}
                  title="Delete"
                >
                  <Trash2 class="size-4" />
                </button>
              </span>
            </Table.Cell>
          </Table.Row>
        {/each}
      </Table.Body>
    </Table.Root>
  {/if}
</div>

{#if shareMenuKey}
  <div
    class="fixed z-50 min-w-[8rem] rounded-sm border bg-popover p-1 shadow-md"
    style="top: {shareMenuPos.top}px; left: {shareMenuPos.left}px; transform: translate(-100%, -100%);"
    onclick={(e) => e.stopPropagation()}
  >
    {#each expiryOptions as opt}
      <button
        class="w-full rounded-sm px-2 py-1.5 text-left text-sm text-popover-foreground hover:bg-accent hover:text-accent-foreground"
        onclick={() => shareObject(shareMenuKey!, opt.seconds)}
      >
        {opt.label}
      </button>
    {/each}
  </div>
{/if}
