<script lang="ts">
	import { cn, type WithElementRef } from "$lib/utils.js";
	import type { HTMLAttributes } from "svelte/elements";

	let {
		ref = $bindable(null),
		class: className,
		children,
		...restProps
	}: WithElementRef<HTMLAttributes<HTMLSpanElement>> = $props();
</script>

<span
	bind:this={ref}
	data-slot="tag"
	class={cn(
		"inline-flex items-center px-2 py-1 text-xs font-bold rounded-sm text-neutral-500 bg-neutral-100 hover:bg-neutral-200 dark:bg-coolgray-100 dark:hover:bg-coolgray-300 cursor-pointer",
		className
	)}
	{...restProps}
>
	{@render children?.()}
</span>
