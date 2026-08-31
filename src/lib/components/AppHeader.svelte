<script lang="ts">
	import type { Snippet } from 'svelte';
	import Logo from './Logo.svelte';

	let { actions }: { actions?: Snippet } = $props();
</script>

<header class="flex items-start justify-between gap-4">
	<div class="flex items-center gap-3.5">
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
