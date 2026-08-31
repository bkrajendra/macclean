<script lang="ts">
	import type { Snippet } from 'svelte';

	// macOS overlay title bar: the traffic lights are drawn natively over the
	// content, so we only reserve a draggable strip and host right-aligned
	// window-level actions.
	let { actions }: { actions?: Snippet } = $props();
</script>

<div class="drag flex h-11 shrink-0 items-center justify-between px-4">
	<div class="h-full w-24"></div>
	<div class="no-drag flex items-center gap-1">
		{@render actions?.()}
	</div>
</div>
