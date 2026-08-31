<script lang="ts">
	import { HelpCircle, Play, Zap } from '@lucide/svelte';
	import Button from '$lib/components/ui/Button.svelte';
	import Segmented from '$lib/components/ui/Segmented.svelte';
	import Select from '$lib/components/ui/Select.svelte';
	import StepHeading from '$lib/components/StepHeading.svelte';
	import PermissionNotice from '$lib/features/permissions/PermissionNotice.svelte';
	import type { Mode, ScopeDescriptor } from '$lib/types/ipc';
	import { settings } from '$lib/stores/settings.svelte';
	import { scan } from '$lib/stores/scan.svelte';

	let {
		scopes,
		onShowRules,
		onShowPermissions
	}: {
		scopes: ScopeDescriptor[];
		onShowRules: () => void;
		onShowPermissions: () => void;
	} = $props();

	let extra = $state(settings.extraRoots.join(', '));

	const modeOptions: ReadonlyArray<{ value: Mode; label: string }> = [
		{ value: 'safe', label: 'Safe' },
		{ value: 'aggressive', label: 'Aggressive' }
	];
	const scopeOptions = $derived(scopes.map((s) => ({ value: s.value, label: s.label })));
	const scopeHint = $derived(scopes.find((s) => s.value === settings.scope)?.description ?? '');
	const modeHint = $derived(
		settings.mode === 'safe'
			? 'Conservative cleanup — caches and dependency folders.'
			: 'Deep scan — also build output, compiled files and *.pyc.'
	);

	function startScan() {
		settings.extraRoots = extra
			.split(',')
			.map((s) => s.trim())
			.filter(Boolean);
		settings.persist();
		void scan.start(settings.options());
	}
</script>

<div class="animate-slide-up space-y-6">
	<StepHeading
		title="Configure your scan"
		subtitle="Choose how and where MacClean should look for unnecessary files."
	/>

	<PermissionNotice onDetails={onShowPermissions} />

	<div class="card p-5">
		<div class="grid gap-5 md:grid-cols-3">
			<div>
				<span class="field-label">Mode</span>
				<Segmented bind:value={settings.mode} options={modeOptions} class="w-full" />
				<p class="mt-2 flex items-center gap-1.5 text-xs text-muted">
					<Zap class="h-3.5 w-3.5 text-brand" />{modeHint}
				</p>
			</div>

			<div>
				<span class="field-label">Scope</span>
				<Select bind:value={settings.scope} options={scopeOptions} ariaLabel="Scan scope" />
				<p class="mt-2 text-xs text-muted">{scopeHint}</p>
			</div>

			<div>
				<span class="field-label">Extra folders</span>
				<input
					class="h-10 w-full rounded-xl border border-line bg-surface-2 px-3 text-sm text-ink placeholder:text-faint focus:border-brand/60 focus:outline-none focus:ring-2 focus:ring-brand/25"
					placeholder="optional — ~/work, /Volumes/Build"
					bind:value={extra}
				/>
				<p class="mt-2 text-xs text-muted">Comma-separated. Added on top of the scope.</p>
			</div>
		</div>
	</div>

	<div class="flex flex-col items-center gap-3 pt-2">
		<Button size="lg" class="min-w-52" onclick={startScan}>
			<Play class="h-4 w-4 fill-current" /> Start scan
		</Button>
		<p class="text-sm text-muted">
			MacClean analyses your system and shows exactly what can be safely cleaned.
		</p>
		<button
			type="button"
			class="no-drag inline-flex items-center gap-1.5 text-xs font-medium text-brand hover:underline"
			onclick={onShowRules}
		>
			<HelpCircle class="h-3.5 w-3.5" /> What does MacClean clean?
		</button>
	</div>
</div>
