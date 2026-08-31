<script lang="ts">
	import Dialog from '$lib/components/ui/Dialog.svelte';
	import CategoryChip from '$lib/components/CategoryChip.svelte';
	import { api } from '$lib/api';
	import type { RuleInfo } from '$lib/types/ipc';

	let { open = $bindable(false) }: { open?: boolean } = $props();

	let rules = $state<RuleInfo[]>([]);
	let loaded = $state(false);

	$effect(() => {
		if (open && !loaded) {
			loaded = true;
			api.getRules().then((r) => (rules = r));
		}
	});

	const groups = $derived([
		{
			key: 'recursive',
			title: 'Recursive patterns',
			note: 'matched anywhere inside the scanned folders'
		},
		{ key: 'home', title: 'User cache locations', note: 'exact paths under your home folder' },
		{ key: 'system', title: 'System cache locations', note: 'Full Mac scope only' }
	]);
</script>

<Dialog
	bind:open
	title="What MacClean cleans"
	description="Every rule, and which mode enables it"
	size="lg"
>
	<div class="space-y-6">
		{#each groups as g (g.key)}
			{@const list = rules.filter((r) => r.scope === g.key)}
			{#if list.length}
				<section>
					<h3 class="font-display text-sm font-bold text-ink">{g.title}</h3>
					<p class="mb-2 text-xs text-muted">{g.note}</p>
					<ul class="divide-y divide-line overflow-hidden rounded-xl border border-line text-sm">
						{#each list as r (r.scope + r.key)}
							<li class="flex items-center justify-between gap-3 px-3.5 py-2">
								<div class="min-w-0">
									<span class="font-mono text-[0.8rem] text-ink">{r.key}</span>
									<span class="ml-2 text-xs text-muted">{r.label}</span>
								</div>
								<div class="flex shrink-0 items-center gap-2">
									<CategoryChip category={r.category} />
									<span
										class="rounded-md px-1.5 py-0.5 text-[0.65rem] font-semibold uppercase tracking-wide {r.safe
											? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300'
											: 'bg-amber-100 text-amber-700 dark:bg-amber-500/15 dark:text-amber-300'}"
									>
										{r.safe ? 'Safe' : 'Aggressive'}
									</span>
								</div>
							</li>
						{/each}
					</ul>
				</section>
			{/if}
		{/each}
		<p class="text-xs text-muted">
			Protected system paths (<code>/System</code>, <code>/Library</code>, your home folder and its
			top-level folders, …) are never listed as candidates and never deleted.
		</p>
	</div>
</Dialog>
