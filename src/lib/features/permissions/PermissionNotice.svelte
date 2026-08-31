<script lang="ts" module>
	// Dismissed for the rest of the session (not persisted — a fresh launch
	// re-checks and may genuinely need attention again).
	let dismissed = $state(false);
</script>

<script lang="ts">
	import { RotateCw, ShieldAlert, X } from '@lucide/svelte';
	import Button from '$lib/components/ui/Button.svelte';
	import { api } from '$lib/api';
	import type { Scope } from '$lib/types/ipc';
	import { system } from '$lib/stores/system.svelte';
	import { toasts } from '$lib/stores/toast.svelte';

	let { scope, onDetails }: { scope: Scope; onDetails?: () => void } = $props();

	const relevant = $derived(scope === 'home' || scope === 'fullMac');
	const show = $derived(
		relevant && !dismissed && system.permissions !== null && !system.permissions.fullDiskAccess
	);
	const adHoc = $derived(system.permissions?.adHocSigned ?? false);
	let openedSettings = $state(false);

	async function openSettings() {
		try {
			await api.openPrivacySettings();
			openedSettings = true;
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
		class="flex flex-wrap items-center gap-x-3 gap-y-2 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm dark:border-amber-500/25 dark:bg-amber-500/10"
	>
		<ShieldAlert class="h-5 w-5 shrink-0 text-amber-600 dark:text-amber-400" />
		<p class="min-w-0 flex-1 text-amber-800 dark:text-amber-200">
			<strong>{scope === 'fullMac' ? 'Full Mac' : 'User home'}</strong> scans reach further with
			<strong>Full Disk Access</strong>. Without it, protected system and app cache locations are
			skipped — and reported, never silently cleaned.{#if openedSettings && adHoc}
				<span class="mt-1 block">
					This build isn't Apple-notarised, so macOS may not keep the grant across updates:
					<strong>remove</strong> any MacClean entry in the Full Disk Access list, add the current
					app with <strong>+</strong>, then <strong>relaunch</strong>.
				</span>
			{:else if openedSettings}
				<span class="mt-1 block">Granted it? <strong>Relaunch</strong> MacClean to apply.</span>
			{/if}
		</p>
		<div class="flex items-center gap-2">
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
			<button
				type="button"
				aria-label="Dismiss"
				class="grid h-7 w-7 place-items-center rounded-lg text-amber-600/70 transition hover:bg-amber-500/10 hover:text-amber-700 dark:text-amber-400/70"
				onclick={() => (dismissed = true)}
			>
				<X class="h-4 w-4" />
			</button>
		</div>
	</div>
{/if}
