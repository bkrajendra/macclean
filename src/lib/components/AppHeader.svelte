<script lang="ts">
	import { getCurrentWindow } from '@tauri-apps/api/window';
	import type { Snippet } from 'svelte';
	import Logo from './Logo.svelte';

	let { actions }: { actions?: Snippet } = $props();

	async function zoom() {
		try {
			await getCurrentWindow().toggleMaximize();
		} catch {
			/* not running inside the Tauri shell */
		}
	}
</script>

<header class="flex items-start justify-between gap-4">
	<!-- svelte-ignore a11y_no_static_element_interactions -->
	<div class="drag flex items-center gap-3.5" role="presentation" ondblclick={zoom}>
		<Logo size={46} />
		<div>
			<h1 class="font-display text-[1.6rem] font-extrabold leading-none tracking-tight text-ink">
				MacClean
			</h1>
			<p class="mt-1.5 text-sm text-muted">
				Find and clear caches, build output and leftovers across your Mac.
			</p>
		</div>
	</div>
	{#if actions}
		<div class="no-drag flex shrink-0 items-center gap-2">
			{@render actions()}
		</div>
	{/if}
</header>
