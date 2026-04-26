<script lang="ts" module>
	import { cn, type WithElementRef } from "$lib/utils.js";
	import type { HTMLAttributes } from "svelte/elements";
	import { type VariantProps, tv } from "tailwind-variants";

	export const calloutVariants = tv({
		base: "relative flex gap-3 p-4 rounded-lg border",
		variants: {
			type: {
				warning:
					"bg-warning-50 border-warning-300 dark:bg-warning-900/30 dark:border-warning-800 [&_.callout-title]:text-warning-800 [&_.callout-body]:text-warning-700 dark:[&_.callout-title]:text-warning-300 dark:[&_.callout-body]:text-warning-200 [&_.callout-icon]:text-warning-700 dark:[&_.callout-icon]:text-warning-300",
				danger:
					"bg-red-50 border-red-300 dark:bg-red-900/30 dark:border-red-800 [&_.callout-title]:text-red-800 [&_.callout-body]:text-red-700 dark:[&_.callout-title]:text-red-300 dark:[&_.callout-body]:text-red-200 [&_.callout-icon]:text-red-700 dark:[&_.callout-icon]:text-red-300",
				info: "bg-blue-50 border-blue-300 dark:bg-blue-900/30 dark:border-blue-800 [&_.callout-title]:text-blue-800 [&_.callout-body]:text-blue-700 dark:[&_.callout-title]:text-blue-300 dark:[&_.callout-body]:text-blue-200 [&_.callout-icon]:text-blue-700 dark:[&_.callout-icon]:text-blue-300",
				success:
					"bg-green-50 border-green-300 dark:bg-green-900/30 dark:border-green-800 [&_.callout-title]:text-green-800 [&_.callout-body]:text-green-700 dark:[&_.callout-title]:text-green-300 dark:[&_.callout-body]:text-green-200 [&_.callout-icon]:text-green-700 dark:[&_.callout-icon]:text-green-300",
			},
		},
		defaultVariants: {
			type: "info",
		},
	});

	export type CalloutType = VariantProps<typeof calloutVariants>["type"];

	export type CalloutProps = WithElementRef<HTMLAttributes<HTMLDivElement>> & {
		type?: CalloutType;
		title?: string;
		icon?: import("svelte").Snippet;
	};
</script>

<script lang="ts">
	let {
		ref = $bindable(null),
		class: className,
		type = "info",
		title,
		icon,
		children,
		...restProps
	}: CalloutProps = $props();
</script>

<div
	bind:this={ref}
	data-slot="callout"
	role="alert"
	class={cn(calloutVariants({ type }), className)}
	{...restProps}
>
	{#if icon}
		<div class="callout-icon shrink-0">{@render icon()}</div>
	{/if}
	<div class="flex-1 text-sm">
		{#if title}
			<div class="callout-title font-bold mb-1">{title}</div>
		{/if}
		<div class="callout-body">{@render children?.()}</div>
	</div>
</div>
