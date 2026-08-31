<script lang="ts">
	import { CircleCheck } from '@lucide/svelte';
	import type { Snippet } from 'svelte';

	let {
		title,
		subtitle,
		complete = false,
		actions
	}: {
		title: string;
		subtitle?: string;
		complete?: boolean;
		actions?: Snippet;
	} = $props();
</script>

<div class="flex items-start justify-between gap-4">
	<div>
		<div class="flex items-center gap-2">
			{#if complete}
				<CircleCheck class="h-6 w-6 text-brand" />
			{/if}
			<h2 class="font-display text-2xl font-extrabold tracking-tight text-ink">
				{title}
			</h2>
		</div>
		{#if subtitle}
			<p class="mt-1 text-sm text-muted">{subtitle}</p>
		{/if}
	</div>
	{#if actions}
		<div class="no-drag flex shrink-0 items-center gap-2">{@render actions()}</div>
	{/if}
</div>
