<script lang="ts">
	import { cn } from "$lib/utils.js";
	import HelpCircle from "lucide-svelte/icons/circle-help";

	type Props = {
		text: string;
		class?: string;
	};

	let { text, class: className }: Props = $props();
</script>

<span class={cn("group relative inline-flex items-center", className)}>
	<HelpCircle class="size-4 text-coollabs dark:text-warning cursor-pointer" />
	<span
		role="tooltip"
		class="hidden group-hover:block absolute left-5 top-0 z-40 max-w-sm text-xs bg-neutral-200 dark:bg-coolgray-400 text-neutral-700 dark:text-neutral-300 rounded-sm p-2 shadow-md"
	>
		{text}
	</span>
</span>
