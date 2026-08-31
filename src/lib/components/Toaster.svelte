<script lang="ts">
	import { CircleAlert, CircleCheck, Info, TriangleAlert, X } from '@lucide/svelte';
	import { fly } from 'svelte/transition';
	import { toasts } from '$lib/stores/toast.svelte';

	const meta = {
		info: { icon: Info, ring: 'text-brand' },
		success: { icon: CircleCheck, ring: 'text-emerald-500' },
		warning: { icon: TriangleAlert, ring: 'text-amber-500' },
		error: { icon: CircleAlert, ring: 'text-rose-500' }
	} as const;
</script>

<div class="pointer-events-none fixed bottom-4 right-4 z-[60] flex w-80 flex-col gap-2">
	{#each toasts.items as t (t.id)}
		{@const M = meta[t.kind]}
		<div
			transition:fly={{ y: 12, duration: 200 }}
			class="card pointer-events-auto flex items-start gap-3 p-3.5 shadow-pop"
		>
			<M.icon class="mt-0.5 h-5 w-5 shrink-0 {M.ring}" />
			<div class="min-w-0 flex-1">
				<p class="text-sm font-semibold text-ink">{t.title}</p>
				{#if t.detail}<p class="mt-0.5 break-words text-xs text-muted">{t.detail}</p>{/if}
			</div>
			<button
				type="button"
				aria-label="Dismiss"
				class="grid h-6 w-6 shrink-0 place-items-center rounded-md text-faint hover:bg-surface-3 hover:text-ink"
				onclick={() => toasts.dismiss(t.id)}
			>
				<X class="h-3.5 w-3.5" />
			</button>
		</div>
	{/each}
</div>
