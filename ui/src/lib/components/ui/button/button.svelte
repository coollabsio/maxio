<script lang="ts" module>
	import { cn, type WithElementRef } from "$lib/utils.js";
	import type { HTMLAnchorAttributes, HTMLButtonAttributes } from "svelte/elements";
	import { type VariantProps, tv } from "tailwind-variants";

	export const buttonVariants = tv({
		base: "inline-flex shrink-0 items-center justify-center gap-2 rounded-sm border-2 text-sm font-medium whitespace-nowrap transition-all outline-none cursor-pointer min-w-fit focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-50 aria-disabled:pointer-events-none aria-disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
		variants: {
			variant: {
				default: "bg-primary text-primary-foreground border-primary hover:bg-primary-hover",
				destructive:
					"bg-destructive/10 text-destructive border-destructive/50 hover:bg-destructive hover:text-white hover:border-destructive",
				outline:
					"bg-transparent text-foreground border-border hover:bg-accent hover:text-accent-foreground",
				secondary: "bg-secondary text-secondary-foreground border-secondary hover:bg-secondary/80",
				ghost: "border-transparent hover:bg-accent hover:text-accent-foreground",
				link: "border-transparent text-primary underline-offset-4 hover:underline",
				brand: "bg-brand text-brand-foreground border border-brand-highlight hover:bg-brand-hover hover:text-brand-foreground",
			},
			size: {
				default: "h-8 px-3 py-1.5 has-[>svg]:px-2",
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
