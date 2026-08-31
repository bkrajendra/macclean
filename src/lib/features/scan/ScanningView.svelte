<script lang="ts">
	import {
		Boxes,
		Clock,
		Database,
		FileSearch,
		FolderSearch,
		HardDrive,
		Radar,
		ScrollText,
		Sparkles,
		Wrench
	} from '@lucide/svelte';
	import Button from '$lib/components/ui/Button.svelte';
	import StepHeading from '$lib/components/StepHeading.svelte';
	import CircularProgress from '$lib/components/CircularProgress.svelte';
	import OrbitField, { type OrbitItem } from '$lib/components/OrbitField.svelte';
	import StatTile from '$lib/components/StatTile.svelte';
	import { iconFor } from '$lib/constants/categories';
	import { formatBytesCompact, formatCount, formatDuration, shortenPath } from '$lib/utils/format';
	import { scan } from '$lib/stores/scan.svelte';
	import { system } from '$lib/stores/system.svelte';

	let now = $state(Date.now());
	$effect(() => {
		const t = setInterval(() => (now = Date.now()), 500);
		return () => clearInterval(t);
	});
	const elapsed = $derived(Math.max(0, now - scan.startedAt));

	const FALLBACK: OrbitItem[] = [
		{ label: 'System caches', icon: HardDrive },
		{ label: 'User caches', icon: Database },
		{ label: 'Logs & reports', icon: ScrollText },
		{ label: 'Dependencies', icon: Boxes },
		{ label: 'Developer tools', icon: Wrench },
		{ label: 'Other files', icon: FileSearch }
	];

	const orbitItems = $derived.by<OrbitItem[]>(() => {
		const buckets = scan.byCategory.slice(0, 6);
		if (buckets.length < 3) return FALLBACK;
		return buckets.map((b) => ({
			label: b.key,
			icon: iconFor(b.key),
			detail: `${formatCount(b.count)} · ${formatBytesCompact(b.bytes)}`,
			status: 'active' as const
		}));
	});

	const currentDir = $derived(
		scan.progress?.currentDir ? shortenPath(scan.progress.currentDir, system.home) : ''
	);
</script>

<div class="animate-fade-in space-y-7">
	<StepHeading
		title="Scanning your Mac"
		subtitle="Looking through the selected locations for unnecessary files…"
	/>

	<OrbitField items={orbitItems}>
		{#snippet ring()}
			<CircularProgress size={240} progress={null}>
				<div class="flex flex-col items-center">
					<Radar class="mb-1 h-7 w-7 text-brand motion-safe:animate-pulse" />
					<p class="font-display text-xl font-extrabold text-ink">Scanning…</p>
					<p class="text-xs text-muted">Analysing your system</p>
					<p class="mt-1 font-display text-2xl font-extrabold text-gradient-brand">
						{formatCount(scan.progress?.itemsFound ?? scan.candidates.length)}
					</p>
					<p class="text-[0.7rem] uppercase tracking-wide text-faint">items found</p>
				</div>
			</CircularProgress>
		{/snippet}
	</OrbitField>

	<div class="flex flex-col items-center gap-3">
		<p class="max-w-full truncate text-sm">
			<span class="font-semibold text-brand">Scanning:</span>
			<span class="font-mono text-muted">{currentDir || '…'}</span>
		</p>
		<Button variant="ghost" onclick={() => scan.cancel()} loading={scan.cancelling}>
			{scan.cancelling ? 'Stopping…' : 'Stop scan'}
		</Button>
	</div>

	<div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
		<StatTile
			icon={FolderSearch}
			label="Folders scanned"
			value={formatCount(scan.progress?.scannedDirs ?? 0)}
			hint="directories walked"
		/>
		<StatTile
			icon={Sparkles}
			label="Reclaimable found"
			value={formatBytesCompact(scan.progress?.bytesFound ?? 0)}
			hint="so far"
		/>
		<StatTile icon={Clock} label="Time elapsed" value={formatDuration(elapsed)} hint="scanning" />
		<StatTile
			icon={FileSearch}
			label="Items found"
			value={formatCount(scan.progress?.itemsFound ?? scan.candidates.length)}
			hint={scan.errors.length
				? `${formatCount(scan.errors.length)} unreadable`
				: 'cleanup candidates'}
		/>
	</div>
</div>
