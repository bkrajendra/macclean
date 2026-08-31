<script lang="ts">
	import type { Snippet } from 'svelte';
	import type { HTMLButtonAttributes } from 'svelte/elements';
	import { cn } from '$lib/utils/cn';

	let {
		label,
		class: klass = '',
		children,
		...rest
	}: { label: string; class?: string; children: Snippet } & HTMLButtonAttributes = $props();
</script>

<button
	{...rest}
	type="button"
	aria-label={label}
	title={label}
	class={cn(
		'no-drag inline-grid h-8 w-8 place-items-center rounded-lg text-muted transition hover:bg-surface-3 hover:text-ink focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/50',
		klass
	)}
>
	{@render children()}
</button>
