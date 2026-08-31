<script lang="ts">
	import type { Snippet } from 'svelte';
	import { clamp } from '$lib/utils/format';

	let {
		size = 260,
		stroke = 14,
		/** 0..1 for a determinate arc; null for an indeterminate spinner */
		progress = null,
		tone = 'brand',
		children
	}: {
		size?: number;
		stroke?: number;
		progress?: number | null;
		tone?: 'brand' | 'magenta';
		children?: Snippet;
	} = $props();

	const uid = 'cp-' + Math.random().toString(36).slice(2, 9);
	const r = $derived((size - stroke) / 2);
	const circumference = $derived(2 * Math.PI * r);
	const frac = $derived(progress === null ? 0.28 : clamp(progress, 0, 1));
	const dash = $derived(circumference * frac);
	const stops = $derived(tone === 'magenta' ? ['#7c5cfc', '#c026d3'] : ['#7c5cfc', '#a855f7']);
</script>

<div class="relative grid place-items-center" style="width:{size}px;height:{size}px">
	<svg
		width={size}
		height={size}
		viewBox="0 0 {size} {size}"
		class={progress === null ? 'motion-safe:animate-[orbit_1.4s_linear_infinite]' : ''}
	>
		<defs>
			<linearGradient id={uid} x1="0%" y1="0%" x2="100%" y2="100%">
				<stop offset="0%" stop-color={stops[0]} />
				<stop offset="100%" stop-color={stops[1]} />
			</linearGradient>
		</defs>
		<circle
			cx={size / 2}
			cy={size / 2}
			{r}
			fill="none"
			stroke="rgb(var(--line))"
			stroke-width={stroke}
		/>
		<circle
			cx={size / 2}
			cy={size / 2}
			{r}
			fill="none"
			stroke="url(#{uid})"
			stroke-width={stroke}
			stroke-linecap="round"
			stroke-dasharray="{dash} {circumference}"
			transform="rotate(-90 {size / 2} {size / 2})"
			class="transition-[stroke-dasharray] duration-500 ease-out"
		/>
	</svg>
	<div class="absolute inset-0 grid place-items-center text-center">
		{@render children?.()}
	</div>
</div>
