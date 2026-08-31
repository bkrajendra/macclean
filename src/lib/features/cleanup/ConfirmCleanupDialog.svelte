<script lang="ts">
	import { TriangleAlert } from '@lucide/svelte';
	import Dialog from '$lib/components/ui/Dialog.svelte';
	import Button from '$lib/components/ui/Button.svelte';
	import CategoryChip from '$lib/components/CategoryChip.svelte';
	import { formatBytes, formatBytesCompact, formatCount } from '$lib/utils/format';
	import { scan } from '$lib/stores/scan.svelte';

	let { open = $bindable(false), onconfirm }: { open?: boolean; onconfirm: () => void } = $props();

	const items = $derived([...scan.selectedItems].sort((a, b) => b.sizeBytes - a.sizeBytes));
	const preview = $derived(items.slice(0, 7));
	const rest = $derived(Math.max(0, items.length - preview.length));

	function confirm() {
		open = false;
		onconfirm();
	}
</script>

<Dialog
	bind:open
	title={`Delete ${formatCount(scan.selectedCount)} item${scan.selectedCount === 1 ? '' : 's'}?`}
	size="md"
>
	<div class="space-y-4">
		<div
			class="flex items-start gap-3 rounded-xl bg-rose-50 px-4 py-3 text-sm text-rose-800 dark:bg-rose-500/10 dark:text-rose-200"
		>
			<TriangleAlert class="mt-0.5 h-5 w-5 shrink-0 text-rose-500" />
			<p>
				This frees about <strong>{formatBytesCompact(scan.selectedBytes)}</strong>. Items are
				removed <strong>permanently</strong> — they are not moved to the Trash.
			</p>
		</div>

		<ul class="divide-y divide-line overflow-hidden rounded-xl border border-line text-sm">
			{#each preview as c (c.id)}
				<li class="flex items-center justify-between gap-3 px-3.5 py-2">
					<div class="min-w-0">
						<div class="flex items-center gap-2">
							<span class="truncate font-medium text-ink">{c.ruleLabel}</span>
							<CategoryChip category={c.category} class="hidden sm:inline-flex" />
						</div>
						<p class="truncate font-mono text-xs text-faint">{c.displayPath}</p>
					</div>
					<span class="shrink-0 text-sm font-semibold tabular-nums text-ink">
						{formatBytes(c.sizeBytes)}
					</span>
				</li>
			{/each}
			{#if rest > 0}
				<li class="px-3.5 py-2 text-xs text-muted">…and {formatCount(rest)} more</li>
			{/if}
		</ul>
	</div>

	{#snippet footer()}
		<Button variant="ghost" onclick={() => (open = false)}>Cancel</Button>
		<Button variant="danger" onclick={confirm}>
			Delete {formatCount(scan.selectedCount)} item{scan.selectedCount === 1 ? '' : 's'}
		</Button>
	{/snippet}
</Dialog>
