<script lang="ts" module>
	import { cn, type WithElementRef } from "$lib/utils.js";
	import type { HTMLAttributes } from "svelte/elements";
	import { type VariantProps, tv } from "tailwind-variants";

	export const cardVariants = tv({
		base: "group bg-card text-card-foreground flex flex-col gap-6 rounded-sm border border-border py-6 shadow-sm min-h-16 transition-colors",
		variants: {
			variant: {
				default: "",
				box: "cursor-pointer hover:bg-neutral-100 dark:hover:bg-coollabs-100 dark:hover:text-white hover:text-black dark:group-hover:[&_[data-slot=card-title]]:text-white dark:group-hover:[&_[data-slot=card-description]]:text-white group-hover:[&_[data-slot=card-description]]:text-black",
				coolbox:
					"rounded cursor-pointer border-neutral-200 dark:border-coolgray-400 hover:ring-2 hover:ring-coollabs dark:hover:ring-warning",
			},
		},
		defaultVariants: {
			variant: "default",
		},
	});

	export type CardVariant = VariantProps<typeof cardVariants>["variant"];

	export type CardProps = WithElementRef<HTMLAttributes<HTMLDivElement>> & {
		variant?: CardVariant;
	};
</script>

<script lang="ts">
	let {
		ref = $bindable(null),
		class: className,
		variant = "default",
		children,
		...restProps
	}: CardProps = $props();
</script>

<div
	bind:this={ref}
	data-slot="card"
	class={cn(cardVariants({ variant }), className)}
	{...restProps}
>
	{@render children?.()}
</div>
