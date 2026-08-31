<script lang="ts">
	import type { LucideIcon } from '@lucide/svelte';

	let {
		icon,
		label,
		value,
		hint,
		accent = 'brand'
	}: {
		icon: LucideIcon;
		label: string;
		value: string;
		hint?: string;
		accent?: 'brand' | 'ok' | 'warn' | 'danger';
	} = $props();

	const Icon = $derived(icon);
	const accents = {
		brand: 'bg-brand-soft text-brand',
		ok: 'bg-emerald-100 text-emerald-600 dark:bg-emerald-500/15 dark:text-emerald-300',
		warn: 'bg-amber-100 text-amber-600 dark:bg-amber-500/15 dark:text-amber-300',
		danger: 'bg-rose-100 text-rose-600 dark:bg-rose-500/15 dark:text-rose-300'
	} as const;
</script>

<article class="card flex items-center gap-3.5 p-4">
	<span class="grid h-12 w-12 shrink-0 place-items-center rounded-2xl {accents[accent]}">
		<Icon class="h-[22px] w-[22px]" />
	</span>
	<div class="min-w-0">
		<p class="text-[0.68rem] font-semibold uppercase tracking-[0.08em] text-faint">{label}</p>
		<p class="mt-0.5 truncate font-display text-xl font-bold text-ink">{value}</p>
		{#if hint}<p class="truncate text-xs text-muted">{hint}</p>{/if}
	</div>
</article>
