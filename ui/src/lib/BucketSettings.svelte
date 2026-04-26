<script lang="ts">
  import { onMount } from 'svelte'
  import { toast } from '$lib/toast'
  import { Callout } from '$lib/components/ui/callout'

  interface Props {
    bucket: string
    onBack: () => void
  }
  let { bucket, onBack }: Props = $props()

  let versioningEnabled = $state(false)
  let loading = $state(true)
  let saving = $state(false)
  let error = $state<string | null>(null)

  async function fetchVersioning() {
    loading = true
    error = null
    try {
      const res = await fetch(`/api/buckets/${encodeURIComponent(bucket)}/versioning`)
      if (res.ok) {
        const data = await res.json()
        versioningEnabled = data.enabled
      } else {
        error = 'Failed to load versioning status'
      }
    } catch (err) {
      console.error('fetchVersioning failed:', err)
      error = 'Failed to connect to server'
    } finally {
      loading = false
    }
  }

  async function toggleVersioning() {
    const newState = !versioningEnabled
    if (versioningEnabled && !newState) {
      if (!confirm('Disable versioning?\n\nThis will permanently delete all old versions. Only the latest version of each file will be kept. This cannot be undone.')) {
        return
      }
    }
    saving = true
    try {
      const res = await fetch(`/api/buckets/${encodeURIComponent(bucket)}/versioning`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: newState }),
      })
      if (res.ok) {
        versioningEnabled = newState
        toast.success(newState ? 'Versioning enabled' : 'Versioning disabled')
      } else {
        const data = await res.json()
        toast.error(data.error || 'Failed to update versioning')
      }
    } catch (err) {
      console.error('toggleVersioning failed:', err)
      toast.error('Failed to connect to server')
    } finally {
      saving = false
    }
  }

  onMount(fetchVersioning)
</script>

<div class="flex flex-col gap-6 max-w-2xl">
  {#if error}
    <Callout type="danger">{error}</Callout>
  {/if}

  {#if versioningEnabled && !loading}
    <Callout type="warning" title="Disabling versioning is destructive">
      Turning versioning off permanently deletes all non-current versions. Only the latest version of each object remains.
    </Callout>
  {/if}

  <div class="flex flex-col gap-4">
    <h3 class="text-sm font-medium text-muted-foreground uppercase tracking-wide">General</h3>

    <div class="flex items-center justify-between">
      <div class="flex flex-col gap-0.5">
        <span class="text-sm font-medium">Versioning</span>
        <span class="text-sm text-muted-foreground">
          {#if loading}
            Loading...
          {:else if versioningEnabled}
            Every upload creates a new version. Deleted files become delete markers.
          {:else}
            Uploading a file overwrites the previous version.
          {/if}
        </span>
      </div>
      {#if !loading}
        <button
          class="relative inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full transition-colors {versioningEnabled ? 'dark:bg-brand bg-foreground' : 'bg-muted-foreground/30'}"
          onclick={toggleVersioning}
          disabled={saving}
          role="switch"
          aria-checked={versioningEnabled}
        >
          <span
            class="pointer-events-none inline-block size-4 rounded-full bg-background shadow transition-transform {versioningEnabled ? 'translate-x-6' : 'translate-x-1'}"
          ></span>
        </button>
      {/if}
    </div>
  </div>
</div>
