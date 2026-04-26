<script lang="ts">
	import { cn, type WithElementRef } from "$lib/utils.js";
	import type { HTMLAttributes } from "svelte/elements";

	let {
		ref = $bindable(null),
		class: className,
		children,
		...restProps
	}: WithElementRef<HTMLAttributes<HTMLElement>> = $props();
</script>

<kbd
	bind:this={ref}
	data-slot="kbd"
	class={cn(
		"inline-block px-2 text-xs rounded-sm border border-dashed border-neutral-700 dark:text-warning",
		className
	)}
	{...restProps}
>
	{@render children?.()}
</kbd>
