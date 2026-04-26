<script lang="ts" module>
	import { cn, type WithElementRef } from "$lib/utils.js";
	import type { HTMLAttributes } from "svelte/elements";
	import { type VariantProps, tv } from "tailwind-variants";

	export const badgeVariants = tv({
		base: "inline-block w-3 h-3 rounded-full leading-none border border-neutral-200 dark:border-black",
		variants: {
			variant: {
				success: "bg-success",
				warning: "bg-warning",
				error: "bg-error",
			},
		},
		defaultVariants: {
			variant: "success",
		},
	});

	export type BadgeVariant = VariantProps<typeof badgeVariants>["variant"];

	export type BadgeProps = WithElementRef<HTMLAttributes<HTMLSpanElement>> & {
		variant?: BadgeVariant;
		label?: string;
	};
</script>

<script lang="ts">
	let {
		ref = $bindable(null),
		class: className,
		variant = "success",
		label,
		...restProps
	}: BadgeProps = $props();

	const textColor = $derived(
		variant === "success"
			? "text-success"
			: variant === "error"
				? "text-error"
				: "text-warning"
	);
</script>

{#if label}
	<span class="inline-flex items-center gap-2">
		<span
			bind:this={ref}
			data-slot="badge"
			class={cn(badgeVariants({ variant }), className)}
			{...restProps}
		></span>
		<span class="text-xs font-bold {textColor}">{label}</span>
	</span>
{:else}
	<span
		bind:this={ref}
		data-slot="badge"
		class={cn(badgeVariants({ variant }), className)}
		{...restProps}
	></span>
{/if}
