<script lang="ts">
	import { RotateCw, ShieldAlert } from '@lucide/svelte';
	import Button from '$lib/components/ui/Button.svelte';
	import { api } from '$lib/api';
	import { system } from '$lib/stores/system.svelte';
	import { toasts } from '$lib/stores/toast.svelte';

	let { onDetails }: { onDetails?: () => void } = $props();

	// Show the notice once we've probed and FDA looks missing. `grantedNow`
	// flips true the moment a re-probe (e.g. on window focus) sees access — the
	// notice then hides itself even before a relaunch.
	const show = $derived(system.permissions !== null && !system.permissions.fullDiskAccess);
	let openedSettings = $state(false);

	async function openSettings() {
		try {
			await api.openPrivacySettings();
			openedSettings = true;
			toasts.info(
				'Opened Privacy & Security',
				'Turn on MacClean under Full Disk Access, then come back — or relaunch.'
			);
		} catch (e) {
			toasts.error('Could not open System Settings', String(e));
		}
	}

	async function relaunch() {
		try {
			await api.restartApp();
		} catch (e) {
			toasts.error('Could not relaunch', String(e));
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
			locations.{#if openedSettings}
				If you just granted it, <strong>relaunch MacClean</strong> to apply the change.{/if}
		</p>
		<div class="flex gap-2">
			{#if onDetails}
				<Button variant="ghost" size="sm" onclick={onDetails}>Details</Button>
			{/if}
			{#if openedSettings}
				<Button variant="ghost" size="sm" onclick={() => system.refreshPermissions()}>
					<RotateCw class="h-3.5 w-3.5" /> Re-check
				</Button>
				<Button variant="subtle" size="sm" onclick={relaunch}>Relaunch</Button>
			{:else}
				<Button variant="subtle" size="sm" onclick={openSettings}>Grant access…</Button>
			{/if}
		</div>
	</div>
{/if}
