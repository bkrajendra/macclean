<script lang="ts">
	import { LayoutGrid } from '@lucide/svelte';
	import { iconFor } from '$lib/constants/categories';
	import type { Category } from '$lib/types/ipc';
	import { formatBytesCompact, formatCount } from '$lib/utils/format';
	import { cn } from '$lib/utils/cn';
	import { scan } from '$lib/stores/scan.svelte';

	const active = $derived(scan.filterCategory);

	function pick(cat: Category | 'all') {
		scan.filterCategory = cat;
	}
</script>

<aside class="card flex w-60 shrink-0 flex-col p-4">
	<h3 class="font-display text-base font-bold text-ink">Cleanup candidates</h3>
	<p class="mb-3 text-xs text-muted">Pick a category to focus the list.</p>

	<nav class="-mx-1 flex-1 space-y-0.5 overflow-y-auto pr-1">
		<button
			type="button"
			onclick={() => pick('all')}
			class={cn(
				'flex w-full items-center gap-2.5 rounded-xl px-2.5 py-2 text-sm transition',
				active === 'all'
					? 'gradient-brand font-semibold text-white shadow-tile'
					: 'text-ink hover:bg-surface-3'
			)}
		>
			<LayoutGrid class="h-4 w-4 shrink-0" />
			<span class="flex-1 text-left">All items</span>
			<span class={cn('text-xs tabular-nums', active === 'all' ? 'text-white/80' : 'text-faint')}>
				{formatCount(scan.totalCount)}
			</span>
		</button>

		{#each scan.byCategory as bucket (bucket.key)}
			{@const Icon = iconFor(bucket.key)}
			{@const on = active === bucket.key}
			<button
				type="button"
				onclick={() => pick(bucket.key)}
				class={cn(
					'flex w-full items-center gap-2.5 rounded-xl px-2.5 py-2 text-sm transition',
					on ? 'gradient-brand font-semibold text-white shadow-tile' : 'text-ink hover:bg-surface-3'
				)}
			>
				<Icon class="h-4 w-4 shrink-0" />
				<span class="flex-1 truncate text-left">{bucket.key}</span>
				<span class={cn('text-xs tabular-nums', on ? 'text-white/80' : 'text-faint')}>
					{formatCount(bucket.count)}
				</span>
			</button>
		{/each}
	</nav>

	<div class="mt-3 border-t border-line pt-3 text-xs text-muted">
		<div class="flex justify-between">
			<span>Reclaimable</span>
			<span class="font-semibold text-ink">{formatBytesCompact(scan.totalBytes)}</span>
		</div>
	</div>
</aside>
