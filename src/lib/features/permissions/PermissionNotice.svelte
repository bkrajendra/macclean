<script lang="ts">
	import { ShieldAlert } from '@lucide/svelte';
	import Button from '$lib/components/ui/Button.svelte';
	import { api } from '$lib/api';
	import { system } from '$lib/stores/system.svelte';
	import { toasts } from '$lib/stores/toast.svelte';

	let { onDetails }: { onDetails?: () => void } = $props();

	const show = $derived(system.permissions !== null && !system.permissions.fullDiskAccess);

	async function openSettings() {
		try {
			await api.openPrivacySettings();
			toasts.info(
				'Opened Privacy & Security',
				'Enable Full Disk Access for MacClean, then re-scan.'
			);
		} catch (e) {
			toasts.error('Could not open System Settings', String(e));
		}
	}
</script>

{#if show}
	<div
		class="flex flex-wrap items-center gap-3 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm dark:border-amber-500/25 dark:bg-amber-500/10"
	>
		<ShieldAlert class="h-5 w-5 shrink-0 text-amber-600 dark:text-amber-400" />
		<p class="min-w-0 flex-1 text-amber-800 dark:text-amber-200">
			Without <strong>Full Disk Access</strong>, MacClean can't see some system and app cache
			locations. Denied paths are reported — never silently skipped.
		</p>
		<div class="flex gap-2">
			{#if onDetails}
				<Button variant="ghost" size="sm" onclick={onDetails}>Details</Button>
			{/if}
			<Button variant="subtle" size="sm" onclick={openSettings}>Grant access…</Button>
		</div>
	</div>
{/if}
