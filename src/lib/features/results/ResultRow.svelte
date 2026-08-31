<script lang="ts">
	import { File, Folder, FolderSymlink, SquareArrowOutUpRight } from '@lucide/svelte';
	import Checkbox from '$lib/components/ui/Checkbox.svelte';
	import CategoryChip from '$lib/components/CategoryChip.svelte';
	import { api } from '$lib/api';
	import type { ScanCandidate } from '$lib/types/ipc';
	import { formatBytes, formatCount } from '$lib/utils/format';
	import { toasts } from '$lib/stores/toast.svelte';

	let {
		candidate,
		selected,
		onToggle
	}: {
		candidate: ScanCandidate;
		selected: boolean;
		onToggle: () => void;
	} = $props();

	async function reveal() {
		try {
			await api.revealInFinder(candidate.path);
		} catch (e) {
			toasts.error('Could not reveal in Finder', String(e));
		}
	}
</script>

<div
	class="group flex h-full items-center gap-3 rounded-xl border border-transparent px-2.5 transition {selected
		? 'bg-brand-soft/60'
		: 'hover:bg-surface-3'}"
>
	<Checkbox checked={selected} onchange={onToggle} label="Select {candidate.ruleLabel}" />

	<span
		class="grid h-9 w-9 shrink-0 place-items-center rounded-xl bg-surface-3 text-muted group-hover:text-brand"
	>
		{#if candidate.isSymlink}
			<FolderSymlink class="h-4 w-4" />
		{:else if candidate.isDir}
			<Folder class="h-4 w-4" />
		{:else}
			<File class="h-4 w-4" />
		{/if}
	</span>

	<div class="min-w-0 flex-1">
		<div class="flex items-center gap-2">
			<span class="truncate text-sm font-semibold text-ink">{candidate.ruleLabel}</span>
			<CategoryChip category={candidate.category} class="hidden sm:inline-flex" />
		</div>
		<p class="truncate font-mono text-xs text-faint">{candidate.displayPath}</p>
	</div>

	<span class="w-20 shrink-0 text-right text-sm font-semibold tabular-nums text-ink">
		{formatBytes(candidate.sizeBytes)}
	</span>
	<span class="hidden w-16 shrink-0 text-right text-sm tabular-nums text-muted lg:block">
		{formatCount(candidate.itemCount)}
	</span>
	<span class="hidden w-32 shrink-0 truncate text-right text-xs text-muted xl:block">
		{candidate.group.replace(/^\/Users\/[^/]+/, '~')}
	</span>

	<button
		type="button"
		aria-label="Show {candidate.ruleLabel} in Finder"
		title="Show in Finder"
		onclick={reveal}
		class="grid h-8 w-8 shrink-0 place-items-center rounded-lg text-faint opacity-0 transition hover:bg-surface-2 hover:text-ink focus-visible:opacity-100 group-hover:opacity-100"
	>
		<SquareArrowOutUpRight class="h-4 w-4" />
	</button>
</div>
