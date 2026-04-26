<script lang="ts">
	import { cn, type WithElementRef } from "$lib/utils.js";
	import type { HTMLThAttributes } from "svelte/elements";

	let {
		ref = $bindable(null),
		class: className,
		children,
		...restProps
	}: WithElementRef<HTMLThAttributes> = $props();
</script>

<th
	bind:this={ref}
	data-slot="table-head"
	class={cn(
		"text-neutral-500 dark:text-neutral-400 h-10 bg-clip-padding px-2 text-start align-middle text-xs font-bold uppercase tracking-wide whitespace-nowrap [&:has([role=checkbox])]:pe-0",
		className
	)}
	{...restProps}
>
	{@render children?.()}
</th>
