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
	});

	$effect(() => {
		// tracks settings.mode / scope / extraRoots via persist()'s reads
		settings.persist();
	});
</script>

<div class="flex min-h-screen flex-col">
	<TitleBar />
	<main class="flex-1 px-3 pb-6 sm:px-5">
		<div class="mx-auto w-full max-w-5xl">
			{@render children()}
		</div>
	</main>
</div>

<Toaster />
