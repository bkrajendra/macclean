<script lang="ts">
	import type { LucideIcon } from '@lucide/svelte';
	import type { Snippet } from 'svelte';

	let {
		icon,
		title,
		message,
		action
	}: { icon: LucideIcon; title: string; message?: string; action?: Snippet } = $props();
	const Icon = $derived(icon);
</script>

<div class="flex flex-col items-center justify-center px-6 py-14 text-center">
	<span class="mb-4 grid h-14 w-14 place-items-center rounded-2xl bg-brand-soft text-brand">
		<Icon class="h-7 w-7" />
	</span>
	<p class="font-display text-base font-bold text-ink">{title}</p>
	{#if message}<p class="mt-1 max-w-sm text-sm text-muted">{message}</p>{/if}
	{#if action}<div class="mt-5">{@render action()}</div>{/if}
</div>
