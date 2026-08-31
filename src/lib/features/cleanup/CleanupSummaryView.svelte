<script lang="ts">
	import { ArrowLeft, CircleCheck, RotateCw, Sparkles } from '@lucide/svelte';
	import Button from '$lib/components/ui/Button.svelte';
	import CircularProgress from '$lib/components/CircularProgress.svelte';
	import { formatBytes, formatBytesCompact, formatCount } from '$lib/utils/format';
	import type { DeleteStatus } from '$lib/types/ipc';
	import { scan } from '$lib/stores/scan.svelte';

	const result = $derived(scan.cleanupResult);

	// animated count-up of reclaimed bytes
	let shown = $state(0);
	$effect(() => {
		const target = result?.deletedBytes ?? 0;
		const reduce = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
		if (reduce || target === 0) {
			shown = target;
			return;
		}
		const start = performance.now();
		const dur = 900;
		let raf = 0;
		const tick = (t: number) => {
			const k = Math.min(1, (t - start) / dur);
			shown = target * (1 - Math.pow(1 - k, 3));
			if (k < 1) raf = requestAnimationFrame(tick);
		};
		raf = requestAnimationFrame(tick);
		return () => cancelAnimationFrame(raf);
	});

	interface Line {
		key: DeleteStatus;
		label: string;
		tone: string;
	}
	const LINES: Line[] = [
		{ key: 'deleted', label: 'Deleted', tone: 'text-emerald-600' },
		{ key: 'alreadyMissing', label: 'Already gone', tone: 'text-muted' },
		{ key: 'skipped', label: 'Skipped', tone: 'text-muted' },
		{ key: 'changed', label: 'Changed since scan', tone: 'text-amber-600' },
		{ key: 'protected', label: 'Protected — not touched', tone: 'text-amber-600' },
		{ key: 'permissionDenied', label: 'Permission denied', tone: 'text-rose-600' },
		{ key: 'failed', label: 'Failed', tone: 'text-rose-600' },
		{ key: 'notInSession', label: 'Not in this scan', tone: 'text-rose-600' }
	];

	const counts = $derived.by(() => {
		const m = new Map<DeleteStatus, number>();
		for (const o of result?.outcomes ?? []) m.set(o.status, (m.get(o.status) ?? 0) + 1);
		return m;
	});
</script>

<div class="flex animate-scale-in flex-col items-center gap-6 py-4 text-center">
	<CircularProgress size={220} progress={1}>
		<div class="flex flex-col items-center">
			<CircleCheck class="mb-1 h-9 w-9 text-emerald-500" />
			<p class="font-display text-xl font-extrabold text-ink">All clean!</p>
			<p class="mt-1 font-display text-3xl font-extrabold text-gradient-brand">
				{formatBytes(shown)}
			</p>
			<p class="text-xs text-muted">
				reclaimed across {formatCount(result?.deletedCount ?? 0)} item{(result?.deletedCount ??
					0) === 1
					? ''
					: 's'}
			</p>
		</div>
	</CircularProgress>

	<div class="card w-full max-w-md divide-y divide-line text-sm">
		{#each LINES as line (line.key)}
			{@const n = counts.get(line.key) ?? 0}
			{#if n > 0}
				<div class="flex items-center justify-between px-4 py-2.5">
					<span class={line.tone}>{line.label}</span>
					<span class="font-semibold tabular-nums text-ink">{formatCount(n)}</span>
				</div>
			{/if}
		{/each}
		<div class="flex items-center justify-between px-4 py-2.5">
			<span class="font-semibold text-ink">Space reclaimed</span>
			<span class="font-semibold tabular-nums text-ink">
				{formatBytesCompact(result?.deletedBytes ?? 0)}
			</span>
		</div>
	</div>

	{#if (result?.failedCount ?? 0) > 0}
		<p class="max-w-md text-xs text-muted">
			Some items couldn't be removed (permission denied or in use). Granting Full Disk Access and
			re-scanning usually resolves this.
		</p>
	{/if}

	<div class="flex gap-3">
		<Button variant="ghost" onclick={() => scan.backToResults()}>
			<ArrowLeft class="h-4 w-4" /> Back to results
		</Button>
		<Button onclick={() => scan.reset()}>
			<RotateCw class="h-4 w-4" /> New scan
		</Button>
	</div>
	<p class="flex items-center gap-1.5 text-xs text-faint">
		<Sparkles class="h-3.5 w-3.5" /> Tip: run a scan monthly to keep build caches in check.
	</p>
</div>
