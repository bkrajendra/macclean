<script lang="ts">
	import { Check, FolderOpen, X } from '@lucide/svelte';
	import Dialog from '$lib/components/ui/Dialog.svelte';
	import Button from '$lib/components/ui/Button.svelte';
	import { api } from '$lib/api';
	import { shortenPath } from '$lib/utils/format';
	import { system } from '$lib/stores/system.svelte';
	import { toasts } from '$lib/stores/toast.svelte';

	let { open = $bindable(false) }: { open?: boolean } = $props();

	const perms = $derived(system.permissions);
	const appPath = $derived(perms?.appPath ?? '');
	const adHoc = $derived(perms?.adHocSigned ?? false);

	async function openSettings() {
		try {
			await api.openPrivacySettings();
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
	async function revealApp() {
		try {
			await api.revealInFinder(appPath);
		} catch (e) {
			toasts.error('Could not reveal in Finder', String(e));
		}
	}
</script>

<Dialog bind:open title="Permissions" description="What MacClean can currently read" size="md">
	<div class="space-y-4 text-sm">
		<div class="flex items-center justify-between rounded-xl bg-surface-3 px-4 py-3">
			<span class="font-semibold text-ink">Full Disk Access</span>
			{#if perms?.fullDiskAccess}
				<span class="inline-flex items-center gap-1.5 font-semibold text-emerald-600">
					<Check class="h-4 w-4" /> Granted
				</span>
			{:else}
				<span class="inline-flex items-center gap-1.5 font-semibold text-amber-600">
					<X class="h-4 w-4" /> Not granted
				</span>
			{/if}
		</div>

		{#if appPath}
			<div
				class="flex items-center justify-between gap-3 rounded-xl border border-line px-4 py-2.5"
			>
				<div class="min-w-0">
					<p class="text-xs text-faint">Running from</p>
					<p class="truncate font-mono text-xs text-ink">{shortenPath(appPath, system.home)}</p>
				</div>
				<button
					type="button"
					class="inline-flex shrink-0 items-center gap-1.5 rounded-lg px-2 py-1 text-xs font-medium text-brand hover:bg-brand-soft"
					onclick={revealApp}
				>
					<FolderOpen class="h-3.5 w-3.5" /> Reveal
				</button>
			</div>
		{/if}

		<ul class="divide-y divide-line overflow-hidden rounded-xl border border-line">
			{#each perms?.probes ?? [] as probe (probe.path)}
				<li class="flex items-center justify-between gap-3 px-4 py-2.5">
					<div class="min-w-0">
						<p class="font-medium text-ink">{probe.label}</p>
						<p class="truncate font-mono text-xs text-faint">{probe.path}</p>
					</div>
					{#if probe.readable}
						<Check class="h-4 w-4 shrink-0 text-emerald-500" />
					{:else}
						<X class="h-4 w-4 shrink-0 text-rose-400" />
					{/if}
				</li>
			{/each}
		</ul>

		<div class="rounded-xl bg-brand-soft px-4 py-3 text-brand">
			<p class="font-semibold">Grant Full Disk Access</p>
			<ol class="mt-1.5 list-decimal space-y-0.5 pl-4 text-[0.82rem] text-brand/90">
				<li>Open System Settings ▸ Privacy &amp; Security ▸ Full Disk Access.</li>
				{#if adHoc}
					<li>
						<strong>Remove</strong> any existing “MacClean” entry with the “–” button (this build isn't
						Apple-notarised, so an old entry won't match the new app).
					</li>
					<li>
						Add the app shown above with <strong>“+”</strong> (use <em>Reveal</em> to find it).
					</li>
				{:else}
					<li>Turn on <strong>MacClean</strong> (add it with “+” if it isn't listed).</li>
				{/if}
				<li><strong>Relaunch MacClean</strong> — macOS applies the grant only to a new launch.</li>
			</ol>
			{#if adHoc}
				<p class="mt-2 text-[0.78rem] text-brand/80">
					A signed &amp; notarised build keeps this grant across updates. See
					<code>docs/signing.md</code>.
				</p>
			{/if}
		</div>
	</div>

	{#snippet footer()}
		<Button variant="ghost" onclick={() => system.refreshPermissions()}>Re-check</Button>
		{#if !perms?.fullDiskAccess}
			<Button variant="ghost" onclick={relaunch}>Relaunch</Button>
		{/if}
		<Button onclick={openSettings}>Open System Settings</Button>
	{/snippet}
</Dialog>
