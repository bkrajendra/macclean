<script lang="ts">
	import { TriangleAlert } from '@lucide/svelte';
	import Button from '$lib/components/ui/Button.svelte';
	import { system } from '$lib/stores/system.svelte';
	import { updater } from '$lib/stores/updater.svelte';

	function installLabel() {
		if (!updater.installing) return 'Install & Restart';
		return updater.progress != null ? `Installing… ${updater.progress}%` : 'Installing…';
	}
</script>

<div
	class="no-drag flex h-9 shrink-0 items-center justify-between border-t border-line px-4 text-xs text-faint"
>
	<span>MacClean{system.info ? ` v${system.info.appVersion}` : ''}</span>

	{#if updater.available}
		<div class="flex items-center gap-2.5">
			{#if updater.error}
				<span class="flex items-center gap-1 text-rose-500">
					<TriangleAlert class="h-3.5 w-3.5" /> Update failed — try again
				</span>
			{:else}
				<span class="font-medium text-brand">Update available — v{updater.version}</span>
			{/if}
			<Button
				size="sm"
				variant="subtle"
				loading={updater.installing}
				onclick={() => updater.install()}
			>
				{installLabel()}
			</Button>
		</div>
	{/if}
</div>
