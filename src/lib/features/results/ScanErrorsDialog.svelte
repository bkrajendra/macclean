<script lang="ts">
	import Dialog from '$lib/components/ui/Dialog.svelte';
	import Button from '$lib/components/ui/Button.svelte';
	import { formatCount } from '$lib/utils/format';
	import type { ScanErrorKind } from '$lib/types/ipc';
	import { scan } from '$lib/stores/scan.svelte';

	let { open = $bindable(false), onGrant }: { open?: boolean; onGrant?: () => void } = $props();

	const KIND_LABEL: Record<ScanErrorKind, string> = {
		permissionDenied: 'Permission denied',
		notFound: 'Vanished during scan',
		io: 'Read error'
	};
	const errors = $derived(scan.summary?.errors ?? []);
	const denied = $derived(scan.summary?.permissionDeniedCount ?? 0);
</script>

<Dialog
	bind:open
	title="Locations that couldn't be read"
	description="These were skipped — nothing here was reported as cleaned"
	size="md"
>
	<div class="space-y-3 text-sm">
		{#if denied > 0}
			<p
				class="rounded-xl bg-amber-50 px-4 py-3 text-amber-800 dark:bg-amber-500/10 dark:text-amber-200"
			>
				{formatCount(denied)} location{denied === 1 ? '' : 's'} were blocked by macOS privacy protection.
				Grant <strong>Full Disk Access</strong> and re-scan to include them.
			</p>
		{/if}
		{#if errors.length === 0}
			<p class="text-muted">No path-level errors were recorded.</p>
		{:else}
			<ul class="max-h-80 divide-y divide-line overflow-y-auto rounded-xl border border-line">
				{#each errors as e (e.path + e.message)}
					<li class="px-3.5 py-2">
						<p class="truncate font-mono text-xs text-ink">{e.path}</p>
						<p class="text-xs text-muted">{KIND_LABEL[e.kind]} — {e.message}</p>
					</li>
				{/each}
			</ul>
		{/if}
	</div>

	{#snippet footer()}
		<Button variant="ghost" onclick={() => (open = false)}>Close</Button>
		{#if onGrant}<Button onclick={onGrant}>Grant access…</Button>{/if}
	{/snippet}
</Dialog>
