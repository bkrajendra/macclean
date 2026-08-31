<script lang="ts">
	let { size = 40, class: klass = '' }: { size?: number; class?: string } = $props();
</script>

<span
	class="inline-grid place-items-center rounded-[28%] shadow-[0_8px_20px_-6px_rgb(124_92_252/0.55)] {klass}"
	style="width:{size}px;height:{size}px;background-image:linear-gradient(140deg,#7c5cfc,#a855f7 55%,#f472b6)"
	aria-hidden="true"
>
	<svg
		width={size * 0.62}
		height={size * 0.62}
		viewBox="0 0 24 24"
		fill="none"
		stroke="white"
		stroke-width="1.9"
		stroke-linecap="round"
		stroke-linejoin="round"
	>
		<path d="M19.4 4.6 13 11" />
		<path d="M15.5 8.5 9 15c-1.7 1.7-1.9 4.2-1.9 4.2s2.5-.2 4.2-1.9l6.5-6.5" />
		<path d="M8.2 15.8 4.6 19.4" />
		<path d="M6.2 12.8 5 12l1-2.4" opacity="0.85" />
		<path
			d="M17.5 3.2 18 1.6 18.6 3.2 20.2 3.8 18.6 4.4 18 6 17.5 4.4 15.9 3.8Z"
			fill="white"
			stroke="none"
		/>
	</svg>
</span>
