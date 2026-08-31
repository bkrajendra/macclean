<script lang="ts">
	import { Clock, FileMinus, PieChart, ShieldCheck, Sparkles } from '@lucide/svelte';
	import StepHeading from '$lib/components/StepHeading.svelte';
	import CircularProgress from '$lib/components/CircularProgress.svelte';
	import OrbitField, { type OrbitItem } from '$lib/components/OrbitField.svelte';
	import StatTile from '$lib/components/StatTile.svelte';
	import { iconFor } from '$lib/constants/categories';
	import {
		formatBytesCompact,
		formatCount,
		formatDuration,
		formatPercent
	} from '$lib/utils/format';
	import { scan } from '$lib/stores/scan.svelte';

	let now = $state(Date.now());
	const startedAt = Date.now();
	$effect(() => {
		const t = setInterval(() => (now = Date.now()), 500);
		return () => clearInterval(t);
	});
	const elapsed = $derived(Math.max(0, now - startedAt));

	const p = $derived(scan.cleanupProgress);
	const fraction = $derived(p && p.total > 0 ? p.done / p.total : 0);

	// selected categories, marked done as the run progresses through the list
	const orbitItems = $derived.by<OrbitItem[]>(() => {
		const cats = new Map<string, number>();
		for (const c of scan.selectedItems)
			cats.set(c.category, (cats.get(c.category) ?? 0) + c.sizeBytes);
		const done = fraction;
		return [...cats.entries()]
			.sort((a, b) => b[1] - a[1])
			.slice(0, 6)
			.map(([cat, bytes], i, arr) => ({
				label: cat,
				icon: iconFor(cat as never),
				detail: formatBytesCompact(bytes),
				status: (i / arr.length < done ? 'done' : 'active') as 'done' | 'active'
			}));
	});
</script>

<div class="animate-fade-in space-y-7">
	<StepHeading
		title="Cleaning your Mac"
		subtitle="Removing the items you selected — please don't quit MacClean."
	/>

	<OrbitField items={orbitItems}>
		{#snippet ring()}
			<CircularProgress size={240} progress={fraction} tone="magenta">
				<div class="flex flex-col items-center">
					<Sparkles class="mb-1 h-7 w-7 text-brand-2" />
					<p class="font-display text-xl font-extrabold text-ink">Cleaning…</p>
					<p class="text-xs text-muted">Removing unnecessary files</p>
					<p class="mt-1 font-display text-3xl font-extrabold text-gradient-brand">
						{formatPercent(fraction)}
					</p>
				</div>
			</CircularProgress>
		{/snippet}
	</OrbitField>

	<div
		class="mx-auto flex max-w-md items-center justify-center gap-2 rounded-xl border border-line bg-surface-2 px-4 py-2.5 text-sm text-muted"
	>
		<ShieldCheck class="h-4 w-4 text-emerald-500" />
		MacClean is removing only the items you selected.
	</div>

	<div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
		<StatTile
			icon={FileMinus}
			label="Items processed"
			value="{formatCount(p?.done ?? 0)} / {formatCount(p?.total ?? 0)}"
			hint="selected for removal"
		/>
		<StatTile
			icon={PieChart}
			label="Space freed"
			value={formatBytesCompact(p?.freedBytes ?? 0)}
			hint="so far"
			accent="ok"
		/>
		<StatTile icon={Clock} label="Time elapsed" value={formatDuration(elapsed)} hint="cleaning" />
		<StatTile
			icon={ShieldCheck}
			label="Status"
			value="Cleaning safely"
			hint="don't quit the app"
			accent="ok"
		/>
	</div>
</div>
