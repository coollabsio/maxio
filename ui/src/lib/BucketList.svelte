<script lang="ts">
  import { onMount } from 'svelte'
  import * as Table from '$lib/components/ui/table'
  import { Button } from '$lib/components/ui/button'
  import { Callout } from '$lib/components/ui/callout'
  import { Badge } from '$lib/components/ui/badge'
  import Database from 'lucide-svelte/icons/database'
  import Plus from 'lucide-svelte/icons/plus'
  import Trash2 from 'lucide-svelte/icons/trash-2'
  import Settings from 'lucide-svelte/icons/settings'
  import { toast } from '$lib/toast'

  interface Props {
    onSelect: (bucket: string) => void
    onSettings: (bucket: string) => void
  }
  let { onSelect, onSettings }: Props = $props()

  interface Bucket {
    name: string
    createdAt: string
    versioning: boolean
    encryption: boolean
  }

  let buckets = $state<Bucket[]>([])
  let loading = $state(true)
  let error = $state<string | null>(null)
  let showCreate = $state(false)
  let newBucketName = $state('')
  let creating = $state(false)

  function autofocus(node: HTMLElement) {
    node.focus()
  }

  async function fetchBuckets() {
    loading = true
    error = null
    try {
      const res = await fetch('/api/buckets')
      if (res.ok) {
        const data = await res.json()
        buckets = data.buckets
      } else {
        error = `Failed to load buckets (${res.status})`
      }
    } catch (err) {
      console.error('fetchBuckets failed:', err)
      error = 'Failed to connect to server'
    } finally {
      loading = false
    }
  }

  async function createBucket() {
    if (!newBucketName.trim()) return
    creating = true
    try {
      const name = newBucketName.trim()
      const res = await fetch('/api/buckets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name }),
      })
      if (res.ok) {
        toast.success(`Bucket "${name}" created`)
        newBucketName = ''
        showCreate = false
        await fetchBuckets()
      } else {
        const data = await res.json()
        toast.error(data.error || `Failed to create bucket (${res.status})`)
      }
    } catch (err) {
      console.error('createBucket failed:', err)
      toast.error('Failed to connect to server')
    } finally {
      creating = false
    }
  }

  async function deleteBucket(name: string, e: Event) {
    e.stopPropagation()
    if (!confirm(`Delete bucket "${name}"? This cannot be undone.`)) return
    try {
      const res = await fetch(`/api/buckets/${encodeURIComponent(name)}`, { method: 'DELETE' })
      if (res.ok) {
        toast.success(`Bucket "${name}" deleted`)
        await fetchBuckets()
      } else {
        const data = await res.json()
        toast.error(data.error || `Failed to delete bucket (${res.status})`)
      }
    } catch (err) {
      console.error('deleteBucket failed:', err)
      toast.error('Failed to connect to server')
    }
  }

  function formatDate(iso: string): string {
    try {
      return new Date(iso).toLocaleString()
    } catch {
      return iso
    }
  }

  onMount(fetchBuckets)
</script>

<div class="flex flex-col gap-4">
  {#if error}
    <Callout type="danger">{error}</Callout>
  {/if}

  <div class="flex items-center gap-2">
    {#if showCreate}
      <form onsubmit={(e) => { e.preventDefault(); createBucket() }} class="flex items-center gap-2">
        <input
          use:autofocus
          type="text"
          bind:value={newBucketName}
          placeholder="bucket-name"
          class="input-cool h-8 w-48"
          disabled={creating}
        />
        <Button type="submit" variant="brand" class="h-8" disabled={creating || !newBucketName.trim()}>
          {creating ? 'Creating...' : 'Create'}
        </Button>
        <Button type="button" variant="ghost" class="h-8" onclick={() => { showCreate = false; newBucketName = '' }}>
          Cancel
        </Button>
      </form>
    {:else}
      <Button variant="brand" class="h-8" onclick={() => (showCreate = true)}>
        <Plus class="size-4 mr-1" /> Create Bucket
      </Button>
    {/if}
  </div>

  {#if loading && buckets.length === 0}
    <p class="text-sm text-muted-foreground">Loading...</p>
  {:else if buckets.length === 0 && !error}
    <Callout type="info">
      <span class="inline-flex items-center gap-2">
        <Database class="size-4 opacity-70" />
        No buckets yet — create your first bucket to get started.
      </span>
    </Callout>
  {:else}
    <Table.Root>
      <Table.Header>
        <Table.Row>
          <Table.Head>Name</Table.Head>
          <Table.Head>Versioning</Table.Head>
          <Table.Head>Encryption</Table.Head>
          <Table.Head>Created</Table.Head>
          <Table.Head class="w-20"></Table.Head>
        </Table.Row>
      </Table.Header>
      <Table.Body>
        {#each buckets as bucket}
          <Table.Row class="cursor-pointer" onclick={() => onSelect(bucket.name)}>
            <Table.Cell class="font-medium">{bucket.name}</Table.Cell>
            <Table.Cell>
              {#if bucket.versioning}
                <Badge variant="success" label="Enabled" />
              {:else}
                <span class="text-xs text-muted-foreground">Disabled</span>
              {/if}
            </Table.Cell>
            <Table.Cell>
              {#if bucket.encryption}
                <span class="inline-flex items-center rounded-sm bg-green-500/10 px-1.5 py-0.5 text-[11px] font-medium text-green-500">Enabled</span>
              {:else}
                <span class="text-xs text-muted-foreground">Disabled</span>
              {/if}
            </Table.Cell>
            <Table.Cell class="text-muted-foreground">{formatDate(bucket.createdAt)}</Table.Cell>
            <Table.Cell class="w-20">
              <div class="flex items-center gap-4">
                <button
                  class="text-muted-foreground hover:text-foreground transition-colors"
                  onclick={(e: Event) => { e.stopPropagation(); onSettings(bucket.name) }}
                  title="Bucket settings"
                >
                  <Settings class="size-4" />
                </button>
                <button
                  class="text-muted-foreground hover:text-destructive transition-colors"
                  onclick={(e: Event) => deleteBucket(bucket.name, e)}
                  title="Delete bucket"
                >
                  <Trash2 class="size-4" />
                </button>
              </div>
            </Table.Cell>
          </Table.Row>
        {/each}
      </Table.Body>
    </Table.Root>
  {/if}
</div>
