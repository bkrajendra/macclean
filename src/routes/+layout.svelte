<script lang="ts">
	import '../app.css';
	import { onMount } from 'svelte';
	import type { Snippet } from 'svelte';
	import TitleBar from '$lib/components/TitleBar.svelte';
	import Toaster from '$lib/components/Toaster.svelte';
	import { settings } from '$lib/stores/settings.svelte';
	import { system } from '$lib/stores/system.svelte';

	let { children }: { children: Snippet } = $props();

	// client-only (ssr = false) — safe to read localStorage here
	settings.hydrate();

	onMount(() => {
		void system.load();

		// Re-probe permissions whenever the window regains focus — catches the
		// user returning from System Settings after granting Full Disk Access.
		let last = 0;
		const recheck = () => {
			const now = Date.now();
			if (now - last < 1500) return;
			last = now;
			void system.refreshPermissions();
		};
		const onVisible = () => {
			if (!document.hidden) recheck();
		};
		window.addEventListener('focus', recheck);
		document.addEventListener('visibilitychange', onVisible);
		return () => {
			window.removeEventListener('focus', recheck);
			document.removeEventListener('visibilitychange', onVisible);
		};
	});

	$effect(() => {
		// tracks settings.mode / scope / extraRoots via persist()'s reads
		settings.persist();
	});
</script>

<div class="flex h-screen flex-col overflow-hidden">
	<TitleBar />
	<main class="flex flex-1 flex-col overflow-y-auto px-4 pb-5 sm:px-6">
		{@render children()}
	</main>
</div>

<Toaster />
