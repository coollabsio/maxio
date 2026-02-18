<script lang="ts">
  import { onMount } from "svelte";
  import Login from "./lib/Login.svelte";
  import BucketList from "./lib/BucketList.svelte";
  import ObjectBrowser from "./lib/ObjectBrowser.svelte";
  import Home from "lucide-svelte/icons/home";
  import LogOut from "lucide-svelte/icons/log-out";
  import PanelLeftClose from "lucide-svelte/icons/panel-left-close";
  import PanelLeftOpen from "lucide-svelte/icons/panel-left-open";

  import ArrowLeft from "lucide-svelte/icons/arrow-left";
  import ChevronRight from "lucide-svelte/icons/chevron-right";
  import Sun from "lucide-svelte/icons/sun";
  import Moon from "lucide-svelte/icons/moon";

  let authenticated = $state<boolean | null>(null);
  let collapsed = $state(localStorage.getItem("sidebar-collapsed") === "true");
  let selectedBucket = $state<string | null>(null);
  let objectBrowserRef = $state<ObjectBrowser | null>(null);
  let currentPrefix = $state("");
  let currentBreadcrumbs = $state<{ label: string; prefix: string }[]>([]);
  let isDark = $state(document.documentElement.classList.contains("dark"));
  let pendingPrefix = $state<string | null>(null);

  $effect(() => {
    if (objectBrowserRef && pendingPrefix) {
      objectBrowserRef.navigateTo(pendingPrefix);
      pendingPrefix = null;
    }
  });

  function applyHash() {
    const hash = window.location.hash.slice(1) || "/";
    if (hash === "/") {
      selectedBucket = null;
      currentPrefix = "";
      currentBreadcrumbs = [];
    } else {
      const parts = hash.slice(1).split("/"); // remove leading /
      const bucket = decodeURIComponent(parts[0]);
      const prefix = parts.slice(1).join("/");
      selectedBucket = bucket;
      if (prefix) {
        if (objectBrowserRef) {
          objectBrowserRef.navigateTo(prefix);
        } else {
          pendingPrefix = prefix;
        }
      }
    }
  }

  function updateHash() {
    if (!selectedBucket) {
      window.location.hash = "/";
    } else if (currentPrefix) {
      window.location.hash = `/${encodeURIComponent(selectedBucket)}/${currentPrefix}`;
    } else {
      window.location.hash = `/${encodeURIComponent(selectedBucket)}`;
    }
  }

  onMount(() => {
    fetch("/api/auth/check")
      .then((res) => { authenticated = res.ok; })
      .catch(() => { authenticated = false; });

    window.addEventListener("hashchange", applyHash);
    if (window.location.hash && window.location.hash !== "#/") {
      applyHash();
    }

    return () => window.removeEventListener("hashchange", applyHash);
  });

  function handleLogin() {
    authenticated = true;
  }

  async function handleLogout() {
    await fetch("/api/auth/logout", { method: "POST" });
    authenticated = false;
  }

  function toggleTheme() {
    isDark = !isDark;
    if (isDark) {
      document.documentElement.classList.add("dark");
      localStorage.setItem("theme", "dark");
    } else {
      document.documentElement.classList.remove("dark");
      localStorage.setItem("theme", "light");
    }
  }

  function selectBucket(name: string) {
    selectedBucket = name;
    currentPrefix = "";
    currentBreadcrumbs = [];
    updateHash();
  }

  function goHome() {
    selectedBucket = null;
    currentPrefix = "";
    currentBreadcrumbs = [];
    updateHash();
  }

  function handlePrefixChange(p: string, crumbs: { label: string; prefix: string }[]) {
    currentPrefix = p;
    currentBreadcrumbs = crumbs;
    updateHash();
  }
</script>

{#if authenticated === null}
  <!-- loading -->
{:else if !authenticated}
  <Login onLogin={handleLogin} />
{:else}
  <div class="relative flex h-screen bg-background">
    <nav
      class="relative flex flex-col border-r bg-sidebar-background transition-[width] duration-200"
      class:w-56={!collapsed}
      class:w-14={collapsed}
      style="border-color: var(--cool-sidebar-border);"
    >
      <!-- Collapse/expand toggle -->
      <button
        onclick={() => { collapsed = !collapsed; localStorage.setItem("sidebar-collapsed", String(collapsed)); }}
        class="absolute top-4 -right-3 z-10 flex size-6 items-center justify-center rounded-full border bg-card text-muted-foreground transition-colors hover:text-foreground"
        style="border-color: var(--cool-sidebar-border);"
        title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
      >
        {#if collapsed}
          <PanelLeftOpen class="size-3" />
        {:else}
          <PanelLeftClose class="size-3" />
        {/if}
      </button>

      <!-- Logo -->
      <div
        class="flex h-14 items-center overflow-hidden"
        class:px-4={!collapsed}
        class:justify-center={collapsed}
        style="border-bottom: 1px solid var(--cool-sidebar-border);"
      >
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" class="size-6 shrink-0">
          <rect width="32" height="32" rx="6" fill="#6b16ed"/>
          <text x="16" y="23" text-anchor="middle" font-family="Inter, system-ui, sans-serif" font-size="18" font-weight="700" fill="white">M</text>
        </svg>
        {#if !collapsed}
          <span
            class="ml-2 text-lg font-bold tracking-tight text-foreground whitespace-nowrap"
            >MaxIO</span
          >
        {/if}
      </div>

      <!-- Nav items -->
      <div class="flex flex-1 flex-col gap-0.5 p-2">
        <button
          onclick={goHome}
          class="flex h-9 w-full items-center rounded-sm text-left text-sm font-medium transition-colors overflow-hidden"
          class:gap-3={!collapsed}
          class:px-3={!collapsed}
          class:justify-center={collapsed}
          style="background: var(--cool-sidebar-active-bg); color: var(--cool-sidebar-active-fg);"
          title="Buckets"
        >
          <Home class="size-4 shrink-0" />
          {#if !collapsed}<span class="whitespace-nowrap">Buckets</span>{/if}
        </button>
      </div>

      <!-- Bottom: theme toggle + logout -->
      <div
        class="flex flex-col gap-0.5 p-2"
        style="border-top: 1px solid var(--cool-sidebar-border);"
      >
        <button
          onclick={toggleTheme}
          class="flex h-9 w-full items-center rounded-sm text-left text-sm font-medium text-muted-foreground transition-colors hover:bg-muted overflow-hidden"
          class:gap-3={!collapsed}
          class:px-3={!collapsed}
          class:justify-center={collapsed}
          title={isDark ? "Switch to light mode" : "Switch to dark mode"}
        >
          {#if isDark}
            <Sun class="size-4 shrink-0" />
          {:else}
            <Moon class="size-4 shrink-0" />
          {/if}
          {#if !collapsed}<span class="whitespace-nowrap">{isDark ? "Light mode" : "Dark mode"}</span>{/if}
        </button>
        <button
          onclick={handleLogout}
          class="flex h-9 w-full items-center rounded-sm text-left text-sm font-medium text-muted-foreground transition-colors hover:bg-muted overflow-hidden"
          class:gap-3={!collapsed}
          class:px-3={!collapsed}
          class:justify-center={collapsed}
          title="Sign out"
        >
          <LogOut class="size-4 shrink-0" />
          {#if !collapsed}<span class="whitespace-nowrap">Sign out</span>{/if}
        </button>
      </div>
    </nav>

    <main class="flex flex-1 flex-col overflow-hidden">
      <!-- Header bar -->
      <div
        class="flex h-14 shrink-0 items-center gap-2 px-6"
        style="border-bottom: 1px solid var(--cool-sidebar-border);"
      >
        {#if selectedBucket}
          <button
            onclick={() => objectBrowserRef?.goUp()}
            class="shrink-0 rounded-sm p-1 text-muted-foreground transition-colors hover:text-foreground"
          >
            <ArrowLeft class="size-4" />
          </button>
          <nav class="flex items-center gap-1 text-sm overflow-x-auto">
            <button
              class="text-muted-foreground hover:text-foreground transition-colors shrink-0"
              onclick={goHome}>Buckets</button
            >
            <ChevronRight class="size-3 shrink-0 text-muted-foreground" />
            {#if currentBreadcrumbs.length > 1}
              {#each currentBreadcrumbs as crumb, i}
                {#if i < currentBreadcrumbs.length - 1}
                  <button
                    class="text-muted-foreground hover:text-foreground transition-colors shrink-0"
                    onclick={() => objectBrowserRef?.navigateTo(crumb.prefix)}
                  >{crumb.label}</button>
                  <ChevronRight class="size-3 shrink-0 text-muted-foreground" />
                {:else}
                  <span class="font-semibold shrink-0">{crumb.label}</span>
                {/if}
              {/each}
            {:else}
              <span class="font-semibold shrink-0">{selectedBucket}</span>
            {/if}
          </nav>
        {:else}
          <h2 class="text-lg font-semibold">Buckets</h2>
        {/if}
      </div>
      <!-- Scrollable content -->
      <div class="flex-1 overflow-auto p-6">
        {#if selectedBucket}
          <ObjectBrowser
            bind:this={objectBrowserRef}
            bucket={selectedBucket}
            onBack={goHome}
            onPrefixChange={handlePrefixChange}
          />
        {:else}
          <BucketList onSelect={selectBucket} />
        {/if}
      </div>
    </main>
  </div>
{/if}
