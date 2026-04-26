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

  let encryptionEnabled = $state(false)
  let encryptionLoading = $state(true)
  let encryptionSaving = $state(false)

  let publicRead = $state(false)
  let publicList = $state(false)
  let publicLoading = $state(true)
  let publicSaving = $state(false)

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

  async function fetchEncryption() {
    encryptionLoading = true
    try {
      const res = await fetch(`/api/buckets/${encodeURIComponent(bucket)}/encryption`)
      if (res.ok) {
        const data = await res.json()
        encryptionEnabled = !!data.enabled
      }
    } catch (err) {
      console.error('fetchEncryption failed:', err)
    } finally {
      encryptionLoading = false
    }
  }

  async function toggleEncryption() {
    const newState = !encryptionEnabled
    if (encryptionEnabled && !newState) {
      if (!confirm('Disable default encryption?\n\nNew uploads will be stored unencrypted. Existing encrypted objects stay encrypted. This cannot be undone for future uploads.')) {
        return
      }
    }
    encryptionSaving = true
    try {
      const res = await fetch(`/api/buckets/${encodeURIComponent(bucket)}/encryption`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: newState }),
      })
      if (res.ok) {
        encryptionEnabled = newState
        toast.success(newState ? 'Default encryption enabled' : 'Default encryption disabled')
      } else {
        const data = await res.json()
        toast.error(data.error || 'Failed to update encryption')
      }
    } catch (err) {
      console.error('toggleEncryption failed:', err)
      toast.error('Failed to connect to server')
    } finally {
      encryptionSaving = false
    }
  }

  async function fetchPublic() {
    publicLoading = true
    try {
      const res = await fetch(`/api/buckets/${encodeURIComponent(bucket)}/public`)
      if (res.ok) {
        const data = await res.json()
        publicRead = !!data.read
        publicList = !!data.list
      }
    } catch (err) {
      console.error('fetchPublic failed:', err)
    } finally {
      publicLoading = false
    }
  }

  async function savePublic(next: { read: boolean; list: boolean }) {
    publicSaving = true
    try {
      const res = await fetch(`/api/buckets/${encodeURIComponent(bucket)}/public`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(next),
      })
      if (res.ok) {
        publicRead = next.read
        publicList = next.list
        return true
      } else {
        const data = await res.json()
        toast.error(data.error || 'Failed to update public access')
      }
    } catch (err) {
      console.error('savePublic failed:', err)
      toast.error('Failed to connect to server')
    } finally {
      publicSaving = false
    }
    return false
  }

  async function togglePublicRead() {
    const newState = !publicRead
    if (newState) {
      if (!confirm('Enable public read?\n\nAnyone with a URL to an object in this bucket can download it without credentials. Only enable if every object in the bucket is safe to share publicly.')) {
        return
      }
    }
    if (await savePublic({ read: newState, list: publicList })) {
      toast.success(newState ? 'Public read enabled' : 'Public read disabled')
    }
  }

  async function togglePublicList() {
    const newState = !publicList
    if (newState) {
      if (!confirm('Enable public listing?\n\nAnyone can list every object key in this bucket without credentials. Keys may reveal sensitive structure.')) {
        return
      }
    }
    if (await savePublic({ read: publicRead, list: newState })) {
      toast.success(newState ? 'Public listing enabled' : 'Public listing disabled')
    }
  }

  onMount(() => {
    fetchVersioning()
    fetchEncryption()
    fetchPublic()
  })
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

    <div class="flex items-center justify-between">
      <div class="flex flex-col gap-0.5">
        <span class="text-sm font-medium">Default encryption (SSE-S3)</span>
        <span class="text-sm text-muted-foreground">
          {#if encryptionLoading}
            Loading...
          {:else if encryptionEnabled}
            New uploads are encrypted at rest with SSE-S3 (AES-256).
          {:else}
            New uploads are stored unencrypted unless the client sends SSE headers.
          {/if}
        </span>
      </div>
      {#if !encryptionLoading}
        <button
          class="relative inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full transition-colors {encryptionEnabled ? 'dark:bg-brand bg-foreground' : 'bg-muted-foreground/30'}"
          onclick={toggleEncryption}
          disabled={encryptionSaving}
          role="switch"
          aria-checked={encryptionEnabled}
        >
          <span
            class="pointer-events-none inline-block size-4 rounded-full bg-background shadow transition-transform {encryptionEnabled ? 'translate-x-6' : 'translate-x-1'}"
          ></span>
        </button>
      {/if}
    </div>

    <div class="flex items-center justify-between">
      <div class="flex flex-col gap-0.5">
        <span class="text-sm font-medium">Public read</span>
        <span class="text-sm text-muted-foreground">
          {#if publicLoading}
            Loading...
          {:else if publicRead}
            Anyone with an object URL can download it without credentials.
          {:else}
            Object downloads require a signed request.
          {/if}
        </span>
      </div>
      {#if !publicLoading}
        <button
          class="relative inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full transition-colors {publicRead ? 'dark:bg-brand bg-foreground' : 'bg-muted-foreground/30'}"
          onclick={togglePublicRead}
          disabled={publicSaving}
          role="switch"
          aria-checked={publicRead}
        >
          <span
            class="pointer-events-none inline-block size-4 rounded-full bg-background shadow transition-transform {publicRead ? 'translate-x-6' : 'translate-x-1'}"
          ></span>
        </button>
      {/if}
    </div>

    <div class="flex items-center justify-between">
      <div class="flex flex-col gap-0.5">
        <span class="text-sm font-medium">Public listing</span>
        <span class="text-sm text-muted-foreground">
          {#if publicLoading}
            Loading...
          {:else if publicList}
            Anyone can list every object key in this bucket without credentials.
          {:else}
            Listing the bucket requires a signed request.
          {/if}
        </span>
      </div>
      {#if !publicLoading}
        <button
          class="relative inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full transition-colors {publicList ? 'dark:bg-brand bg-foreground' : 'bg-muted-foreground/30'}"
          onclick={togglePublicList}
          disabled={publicSaving}
          role="switch"
          aria-checked={publicList}
        >
          <span
            class="pointer-events-none inline-block size-4 rounded-full bg-background shadow transition-transform {publicList ? 'translate-x-6' : 'translate-x-1'}"
          ></span>
        </button>
      {/if}
    </div>
  </div>
</div>
