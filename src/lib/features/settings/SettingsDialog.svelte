<script lang="ts">
	import Dialog from '$lib/components/ui/Dialog.svelte';
	import Segmented from '$lib/components/ui/Segmented.svelte';
	import Select from '$lib/components/ui/Select.svelte';
	import Button from '$lib/components/ui/Button.svelte';
	import type { Mode, ScopeDescriptor } from '$lib/types/ipc';
	import { settings } from '$lib/stores/settings.svelte';

	let { open = $bindable(false), scopes }: { open?: boolean; scopes: ScopeDescriptor[] } = $props();

	let extra = $state(settings.extraRoots.join(', '));

	function save() {
		settings.extraRoots = extra
			.split(',')
			.map((s) => s.trim())
			.filter(Boolean);
		settings.persist();
		open = false;
	}

	const modeOptions: ReadonlyArray<{ value: Mode; label: string }> = [
		{ value: 'safe', label: 'Safe' },
		{ value: 'aggressive', label: 'Aggressive' }
	];
</script>

<Dialog bind:open title="Scan defaults" description="Used the next time you start a scan" size="md">
	<div class="space-y-5">
		<div>
			<span class="field-label">Default mode</span>
			<Segmented bind:value={settings.mode} options={modeOptions} />
			<p class="mt-1.5 text-xs text-muted">
				{settings.mode === 'safe'
					? 'Conservative: caches and dependency folders only.'
					: 'Adds build output, compiled artefacts and *.pyc files.'}
			</p>
		</div>

		<div>
			<span class="field-label">Default scope</span>
			<Select
				bind:value={settings.scope}
				options={scopes.map((s) => ({ value: s.value, label: s.label }))}
				ariaLabel="Default scope"
			/>
			<p class="mt-1.5 text-xs text-muted">
				{scopes.find((s) => s.value === settings.scope)?.description ?? ''}
			</p>
		</div>

		<div>
			<span class="field-label">Extra folders to scan</span>
			<input
				class="w-full rounded-xl border border-line bg-surface-2 px-3 py-2 text-sm text-ink focus:border-brand/60 focus:outline-none focus:ring-2 focus:ring-brand/25"
				placeholder="~/work/scratch, /Volumes/Build/cache"
				bind:value={extra}
			/>
			<p class="mt-1.5 text-xs text-muted">
				Comma-separated. Added on top of the scope's roots (same as
				<code>MACCLEAN_EXTRA_SCAN_ROOTS</code>).
			</p>
		</div>
	</div>

	{#snippet footer()}
		<Button variant="ghost" onclick={() => (open = false)}>Cancel</Button>
		<Button onclick={save}>Save</Button>
	{/snippet}
</Dialog>
