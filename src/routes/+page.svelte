<script lang="ts">
	import { onDestroy, onMount } from 'svelte';
	import { Info, ListChecks, Settings2, ShieldCheck } from '@lucide/svelte';
	import AppHeader from '$lib/components/AppHeader.svelte';
	import IconButton from '$lib/components/ui/IconButton.svelte';
	import DashboardView from '$lib/features/dashboard/DashboardView.svelte';
	import ScanningView from '$lib/features/scan/ScanningView.svelte';
	import ResultsView from '$lib/features/results/ResultsView.svelte';
	import CleaningView from '$lib/features/cleanup/CleaningView.svelte';
	import CleanupSummaryView from '$lib/features/cleanup/CleanupSummaryView.svelte';
	import ConfirmCleanupDialog from '$lib/features/cleanup/ConfirmCleanupDialog.svelte';
	import ScanErrorsDialog from '$lib/features/results/ScanErrorsDialog.svelte';
	import PermissionsDialog from '$lib/features/permissions/PermissionsDialog.svelte';
	import RulesDialog from '$lib/features/rules/RulesDialog.svelte';
	import AboutDialog from '$lib/features/about/AboutDialog.svelte';
	import SettingsDialog from '$lib/features/settings/SettingsDialog.svelte';
	import { api } from '$lib/api';
	import { FALLBACK_SCOPES } from '$lib/constants/scopes';
	import type { ScopeDescriptor } from '$lib/types/ipc';
	import { scan } from '$lib/stores/scan.svelte';
	import { system } from '$lib/stores/system.svelte';
	import { toasts } from '$lib/stores/toast.svelte';

	let scopes = $state<ScopeDescriptor[]>(FALLBACK_SCOPES);
	let showConfirm = $state(false);
	let showErrors = $state(false);
	let showPermissions = $state(false);
	let showRules = $state(false);
	let showAbout = $state(false);
	let showSettings = $state(false);

	onMount(async () => {
		try {
			scopes = await api.listScopes();
		} catch {
			scopes = FALLBACK_SCOPES;
		}
	});
	onDestroy(() => void scan.dispose());

	let notifiedScanId = '';
	$effect(() => {
		const s = scan.summary;
		if (s && s.scanId !== notifiedScanId && scan.phase === 'results') {
			notifiedScanId = s.scanId;
			if (s.state === 'cancelled') {
				toasts.warning('Scan stopped', `${s.totalCount} items kept and still selectable.`);
			} else if (s.errors.length || s.permissionDeniedCount) {
				toasts.warning(
					'Scan finished with warnings',
					`${s.permissionDeniedCount + s.errors.length} locations could not be read.`
				);
			}
			void system.refreshPermissions();
		}
	});

	let notifiedCleanup = '';
	$effect(() => {
		const r = scan.cleanupResult;
		if (r && scan.phase === 'summary' && r.scanId + r.deletedCount !== notifiedCleanup) {
			notifiedCleanup = r.scanId + r.deletedCount;
			if (r.failedCount > 0) {
				toasts.error(
					'Some items could not be removed',
					`${r.failedCount} failed, ${r.deletedCount} cleaned.`
				);
			} else {
				toasts.success('Cleanup complete', `Reclaimed space across ${r.deletedCount} items.`);
			}
		}
	});
</script>

<div class="card mt-1 flex min-h-[calc(100vh-5.5rem)] flex-col p-5 sm:p-7">
	<AppHeader>
		{#snippet actions()}
			<IconButton label="What MacClean cleans" onclick={() => (showRules = true)}>
				<ListChecks class="h-4 w-4" />
			</IconButton>
			<IconButton label="Permissions" onclick={() => (showPermissions = true)}>
				<ShieldCheck class="h-4 w-4" />
			</IconButton>
			<IconButton label="Scan defaults" onclick={() => (showSettings = true)}>
				<Settings2 class="h-4 w-4" />
			</IconButton>
			<IconButton label="About MacClean" onclick={() => (showAbout = true)}>
				<Info class="h-4 w-4" />
			</IconButton>
		{/snippet}
	</AppHeader>

	<div class="mt-7 flex flex-1 flex-col">
		{#if scan.phase === 'idle'}
			<DashboardView
				{scopes}
				onShowRules={() => (showRules = true)}
				onShowPermissions={() => (showPermissions = true)}
			/>
		{:else if scan.phase === 'scanning'}
			<ScanningView />
		{:else if scan.phase === 'results'}
			<ResultsView
				onConfirmClean={() => (showConfirm = true)}
				onShowErrors={() => (showErrors = true)}
			/>
		{:else if scan.phase === 'cleaning'}
			<CleaningView />
		{:else if scan.phase === 'summary'}
			<CleanupSummaryView />
		{/if}
	</div>
</div>

<ConfirmCleanupDialog bind:open={showConfirm} onconfirm={() => scan.clean()} />
<ScanErrorsDialog
	bind:open={showErrors}
	onGrant={() => {
		showErrors = false;
		showPermissions = true;
	}}
/>
<PermissionsDialog bind:open={showPermissions} />
<RulesDialog bind:open={showRules} />
<AboutDialog bind:open={showAbout} />
<SettingsDialog bind:open={showSettings} {scopes} />
