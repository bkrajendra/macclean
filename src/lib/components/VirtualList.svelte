<script lang="ts" generics="T">
	import type { Snippet } from 'svelte';

	let {
		items,
		rowHeight = 64,
		overscan = 8,
		key,
		class: klass = '',
		row
	}: {
		items: T[];
		rowHeight?: number;
		overscan?: number;
		key: (item: T) => string | number;
		class?: string;
		row: Snippet<[T, number]>;
	} = $props();

	let el = $state<HTMLDivElement | null>(null);
	let scrollTop = $state(0);
	let viewport = $state(600);

	const total = $derived(items.length * rowHeight);
	const start = $derived(Math.max(0, Math.floor(scrollTop / rowHeight) - overscan));
	const visibleCount = $derived(
		Math.min(items.length - start, Math.ceil(viewport / rowHeight) + overscan * 2)
	);
	const slice = $derived(items.slice(start, start + Math.max(0, visibleCount)));

	function onscroll() {
		if (el) scrollTop = el.scrollTop;
	}

	$effect(() => {
		if (!el) return;
		const node = el;
		const ro = new ResizeObserver(() => (viewport = node.clientHeight));
		ro.observe(node);
		viewport = node.clientHeight;
		return () => ro.disconnect();
	});

	// keep the scroll offset valid when the list shrinks (after a delete)
	$effect(() => {
		if (el && scrollTop > total) el.scrollTop = Math.max(0, total - viewport);
	});
</script>

<div bind:this={el} {onscroll} class="overflow-y-auto {klass}">
	<div style="height:{total}px;position:relative;width:100%">
		<div style="position:absolute;left:0;right:0;transform:translateY({start * rowHeight}px)">
			{#each slice as item, i (key(item))}
				<div style="height:{rowHeight}px">{@render row(item, start + i)}</div>
			{/each}
		</div>
	</div>
</div>
