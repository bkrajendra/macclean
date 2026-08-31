<script lang="ts">
	import {
		Clock,
		FileWarning,
		FolderTree,
		Layers,
		RotateCw,
		Sparkles,
		Trash2
	} from '@lucide/svelte';
	import Button from '$lib/components/ui/Button.svelte';
	import StepHeading from '$lib/components/StepHeading.svelte';
	import StatTile from '$lib/components/StatTile.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import VirtualList from '$lib/components/VirtualList.svelte';
	import ResultsSidebar from './ResultsSidebar.svelte';
	import ResultsToolbar from './ResultsToolbar.svelte';
	import ResultRow from './ResultRow.svelte';
	import type { ScanCandidate } from '$lib/types/ipc';
	import { formatBytesCompact, formatCount, formatDuration } from '$lib/utils/format';
	import { scan } from '$lib/stores/scan.svelte';

	let { onConfirmClean, onShowErrors }: { onConfirmClean: () => void; onShowErrors: () => void } =
		$props();

	const summary = $derived(scan.summary);
	const scanMs = $derived(summary ? Math.max(0, summary.finishedAtMs - summary.startedAtMs) : 0);
	const cancelled = $derived(summary?.state === 'cancelled');
	const empty = $derived(scan.candidates.length === 0);
	const unreadable = $derived(
		(summary?.permissionDeniedCount ?? 0) + (summary?.errors.length ?? 0)
	);
</script>

<div class="flex h-full flex-col gap-5">
	<StepHeading
		complete
		title={cancelled ? 'Scan stopped' : 'Scan complete'}
		subtitle={empty
			? 'Nothing to clean was found in the selected locations.'
			: `Found ${formatCount(scan.totalCount)} items using ${formatBytesCompact(scan.totalBytes)} that can be cleaned.`}
	>
		{#snippet actions()}
			<Button variant="ghost" size="sm" onclick={() => scan.reset()}>
				<RotateCw class="h-3.5 w-3.5" /> New scan
			</Button>
		{/snippet}
	</StepHeading>

	{#if unreadable > 0}
		<button
			type="button"
			onclick={onShowErrors}
			class="flex items-center gap-2 self-start rounded-lg bg-amber-100 px-3 py-1.5 text-xs font-medium text-amber-800 hover:brightness-95 dark:bg-amber-500/15 dark:text-amber-300"
		>
			<FileWarning class="h-3.5 w-3.5" />
			{formatCount(unreadable)} location{unreadable === 1 ? '' : 's'} couldn't be read — see details
		</button>
	{/if}

	{#if empty}
		<div class="card">
			<EmptyState
				icon={Sparkles}
				title="You're all clean here"
				message="No caches, build output or leftovers matched in this scope. Try a wider scope or Aggressive mode."
			>
				{#snippet action()}
					<Button onclick={() => scan.reset()}>Start a new scan</Button>
				{/snippet}
			</EmptyState>
		</div>
	{:else}
		<div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
			<StatTile
				icon={Layers}
				label="Items found"
				value={formatCount(scan.totalCount)}
				hint="files & folders"
			/>
			<StatTile
				icon={Sparkles}
				label="Space to clean"
				value={formatBytesCompact(scan.totalBytes)}
				hint="reclaimable"
			/>
			<StatTile
				icon={FolderTree}
				label="Categories"
				value={formatCount(scan.byCategory.length)}
				hint="matched"
			/>
			<StatTile
				icon={Clock}
				label="Scan time"
				value={formatDuration(scanMs)}
				hint={cancelled ? 'stopped early' : 'completed'}
			/>
		</div>

		<div class="flex min-h-0 flex-1 gap-4">
			<ResultsSidebar />

			<section class="card flex min-h-0 flex-1 flex-col overflow-hidden">
				<ResultsToolbar />
				{#if scan.visible.length === 0}
					<EmptyState
						icon={Sparkles}
						title="Nothing matches"
						message="No items match the current search or category filter."
					/>
				{:else}
					<VirtualList
						items={scan.visible}
						rowHeight={64}
						key={(c: ScanCandidate) => c.id}
						class="flex-1 px-2 py-1.5"
					>
						{#snippet row(candidate: ScanCandidate)}
							<div class="px-1.5 py-1">
								<ResultRow
									{candidate}
									selected={scan.selectedIds.has(candidate.id)}
									onToggle={() => scan.toggle(candidate.id)}
								/>
							</div>
						{/snippet}
					</VirtualList>
				{/if}
			</section>
		</div>

		<div class="flex flex-wrap items-center justify-between gap-4">
			<p class="text-sm text-muted">
				<span class="font-semibold text-ink">{formatCount(scan.selectedCount)}</span> selected ·
				<span class="font-semibold text-ink">{formatBytesCompact(scan.selectedBytes)}</span>
				to reclaim
			</p>
			<Button variant="danger" disabled={scan.selectedCount === 0} onclick={onConfirmClean}>
				<Trash2 class="h-4 w-4" /> Clean selected
			</Button>
		</div>
	{/if}
</div>
