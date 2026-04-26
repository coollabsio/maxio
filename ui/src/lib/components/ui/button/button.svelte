<script lang="ts" module>
	import { cn, type WithElementRef } from "$lib/utils.js";
	import type { HTMLAnchorAttributes, HTMLButtonAttributes } from "svelte/elements";
	import { type VariantProps, tv } from "tailwind-variants";

	export const buttonVariants = tv({
		base: "inline-flex shrink-0 items-center justify-center gap-2 rounded-sm border-2 text-sm font-medium whitespace-nowrap transition-all outline-none cursor-pointer min-w-fit focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-coollabs dark:focus-visible:ring-warning focus-visible:ring-offset-2 focus-visible:ring-offset-background dark:focus-visible:ring-offset-base disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-50 aria-disabled:pointer-events-none aria-disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
		variants: {
			variant: {
				default:
					"bg-white text-black border-neutral-200 hover:bg-neutral-100 dark:bg-coolgray-100 dark:text-white dark:border-coolgray-300 dark:hover:bg-coolgray-200",
				highlighted:
					"text-coollabs-200 bg-coollabs-50 border-coollabs hover:bg-coollabs hover:text-white dark:text-white dark:bg-coollabs/20 dark:border-coollabs-100 dark:hover:bg-coollabs-100 dark:hover:text-white",
				destructive:
					"text-red-800 bg-red-50 border-red-300 hover:bg-red-300 hover:text-white dark:text-red-300 dark:bg-red-900/30 dark:border-red-800 dark:hover:bg-red-800 dark:hover:text-white",
				outline:
					"bg-transparent text-black border-neutral-200 hover:bg-neutral-100 dark:text-white dark:border-coolgray-300 dark:hover:bg-coolgray-200",
				secondary:
					"bg-neutral-100 text-black border-neutral-200 hover:bg-neutral-200 dark:bg-coolgray-200 dark:text-white dark:border-coolgray-300 dark:hover:bg-coolgray-300",
				ghost:
					"border-transparent text-black hover:bg-neutral-100 dark:text-white dark:hover:bg-coolgray-200",
				link: "border-transparent text-coollabs dark:text-warning underline-offset-4 hover:underline",
				brand:
					"bg-brand text-brand-foreground border-brand-highlight hover:bg-brand-hover hover:text-brand-foreground",
			},
			size: {
				default: "h-8 px-2 py-1 has-[>svg]:px-2",
				sm: "h-7 gap-1.5 px-2.5 has-[>svg]:px-2",
				lg: "h-10 px-6 has-[>svg]:px-4",
				icon: "size-8",
				"icon-sm": "size-7",
				"icon-lg": "size-10",
			},
		},
		defaultVariants: {
			variant: "default",
			size: "default",
		},
	});

	export type ButtonVariant = VariantProps<typeof buttonVariants>["variant"];
	export type ButtonSize = VariantProps<typeof buttonVariants>["size"];

	export type ButtonProps = WithElementRef<HTMLButtonAttributes> &
		WithElementRef<HTMLAnchorAttributes> & {
			variant?: ButtonVariant;
			size?: ButtonSize;
		};
</script>

<script lang="ts">
	let {
		class: className,
		variant = "default",
		size = "default",
		ref = $bindable(null),
		href = undefined,
		type = "button",
		disabled,
		children,
		...restProps
	}: ButtonProps = $props();
</script>

{#if href}
	<a
		bind:this={ref}
		data-slot="button"
		class={cn(buttonVariants({ variant, size }), className)}
		href={disabled ? undefined : href}
		aria-disabled={disabled}
		role={disabled ? "link" : undefined}
		tabindex={disabled ? -1 : undefined}
		{...restProps}
	>
		{@render children?.()}
	</a>
{:else}
	<button
		bind:this={ref}
		data-slot="button"
		class={cn(buttonVariants({ variant, size }), className)}
		{type}
		{disabled}
		{...restProps}
	>
		{@render children?.()}
	</button>
{/if}
