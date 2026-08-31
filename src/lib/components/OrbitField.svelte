<script lang="ts">
	import { Check, LoaderCircle, type LucideIcon } from '@lucide/svelte';
	import type { Snippet } from 'svelte';

	export interface OrbitItem {
		label: string;
		icon: LucideIcon;
		detail?: string;
		status?: 'idle' | 'active' | 'done';
	}

	let { items, ring }: { items: OrbitItem[]; ring: Snippet } = $props();

	const mid = $derived(Math.ceil(items.length / 2));
	const left = $derived(items.slice(0, mid));
	const right = $derived(items.slice(mid));
</script>

<div class="relative mx-auto flex max-w-4xl items-center justify-center gap-4 py-2 sm:gap-8">
	<svg
		class="pointer-events-none absolute inset-0 h-full w-full opacity-70"
		aria-hidden="true"
		preserveAspectRatio="none"
		viewBox="0 0 800 360"
	>
		<g
			fill="none"
			stroke="rgb(var(--line))"
			stroke-width="1.5"
			stroke-dasharray="2 7"
			stroke-linecap="round"
		>
			<ellipse
				cx="400"
				cy="180"
				rx="330"
				ry="120"
				class="motion-safe:animate-orbit"
				style="transform-origin:400px 180px"
			/>
			<ellipse
				cx="400"
				cy="180"
				rx="260"
				ry="95"
				class="motion-safe:animate-orbit-rev"
				style="transform-origin:400px 180px"
			/>
		</g>
	</svg>

	{#snippet chip(item: OrbitItem, align: 'left' | 'right')}
		{@const Icon = item.icon}
		<li class="flex items-center gap-3 {align === 'right' ? 'flex-row-reverse text-right' : ''}">
			<span
				class="grid h-11 w-11 shrink-0 place-items-center rounded-2xl border border-line bg-surface-2 text-brand shadow-tile"
			>
				<Icon class="h-5 w-5" />
			</span>
			<div class="min-w-0">
				<p class="truncate text-sm font-semibold text-ink">{item.label}</p>
				{#if item.detail}<p class="truncate text-xs text-muted">{item.detail}</p>{/if}
			</div>
			{#if item.status === 'done'}
				<span class="grid h-5 w-5 place-items-center rounded-full gradient-brand text-white">
					<Check class="h-3 w-3" stroke-width={3.5} />
				</span>
			{:else if item.status === 'active'}
				<LoaderCircle class="h-4 w-4 shrink-0 animate-spin text-brand" />
			{/if}
		</li>
	{/snippet}

	<ul class="relative z-10 flex w-44 flex-col gap-7 sm:w-52">
		{#each left as item (item.label)}{@render chip(item, 'left')}{/each}
	</ul>

	<div class="relative z-10 shrink-0">{@render ring()}</div>

	<ul class="relative z-10 flex w-44 flex-col items-end gap-7 sm:w-52">
		{#each right as item (item.label)}{@render chip(item, 'right')}{/each}
	</ul>
</div>
