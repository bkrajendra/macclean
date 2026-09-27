<script lang="ts">
	import { ShieldAlert } from '@lucide/svelte';
	import Dialog from '$lib/components/ui/Dialog.svelte';
	import Button from '$lib/components/ui/Button.svelte';
	import Checkbox from '$lib/components/ui/Checkbox.svelte';
	import CategoryChip from '$lib/components/CategoryChip.svelte';
	import { formatBytes, formatBytesCompact, formatCount } from '$lib/utils/format';
	import { scan } from '$lib/stores/scan.svelte';

	let { open = $bindable(false), onconfirm }: { open?: boolean; onconfirm: () => void } = $props();

	const items = $derived([...scan.selectedItems].sort((a, b) => b.sizeBytes - a.sizeBytes));
	const preview = $derived(items.slice(0, 7));
	const rest = $derived(Math.max(0, items.length - preview.length));

	// Re-armed on every open so acknowledging once never carries over to the
	// next (possibly much larger, or different) selection.
	let acknowledged = $state(false);
	$effect(() => {
		if (open) acknowledged = false;
	});

	function confirm() {
		if (!acknowledged) return;
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
			class="flex items-start gap-3 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3.5 text-sm text-rose-800 dark:border-rose-500/25 dark:bg-rose-500/10 dark:text-rose-200"
		>
			<ShieldAlert class="mt-0.5 h-6 w-6 shrink-0 text-rose-500" />
			<div class="space-y-1">
				<p class="font-semibold">This cannot be undone.</p>
				<p>
					This frees about <strong>{formatBytesCompact(scan.selectedBytes)}</strong> across
					<strong>{formatCount(scan.selectedCount)}</strong> item{scan.selectedCount === 1
						? ''
						: 's'}. They are deleted <strong>permanently</strong> — not moved to the Trash, and not recoverable
					by MacClean or macOS afterward. Double-check the list below before continuing.
				</p>
			</div>
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
		<div class="flex w-full flex-col gap-3">
			<label class="flex cursor-pointer items-start gap-2.5 rounded-xl bg-surface-3 px-3.5 py-3">
				<Checkbox
					checked={acknowledged}
					onchange={(v) => (acknowledged = v)}
					label="I understand this permanently deletes these items"
					class="mt-0.5"
				/>
				<span class="text-sm text-ink">
					I understand this <strong>permanently deletes</strong> these items and cannot be undone.
				</span>
			</label>
			<div class="flex items-center justify-end gap-3">
				<Button variant="ghost" onclick={() => (open = false)}>Cancel</Button>
				<Button variant="danger" disabled={!acknowledged} onclick={confirm}>
					Delete {formatCount(scan.selectedCount)} item{scan.selectedCount === 1 ? '' : 's'}
				</Button>
			</div>
		</div>
	{/snippet}
</Dialog>
