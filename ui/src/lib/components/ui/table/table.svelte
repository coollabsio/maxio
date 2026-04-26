<script lang="ts">
	import type { HTMLTableAttributes } from "svelte/elements";
	import { cn, type WithElementRef } from "$lib/utils.js";

	let {
		ref = $bindable(null),
		class: className,
		children,
		...restProps
	}: WithElementRef<HTMLTableAttributes> = $props();
</script>

<div data-slot="table-container" class="relative w-full overflow-x-auto">
	<table
		bind:this={ref}
		data-slot="table"
		class={cn(
			"min-w-full caption-bottom text-sm divide-y divide-neutral-300 dark:divide-coolgray-200",
			className
		)}
		{...restProps}
	>
		{@render children?.()}
	</table>
</div>
