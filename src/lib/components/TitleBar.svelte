<script lang="ts">
	import type { Snippet } from 'svelte';

	// macOS overlay title bar: the traffic lights float over the content, so we
	// reserve a draggable strip. `data-tauri-drag-region` is Tauri's drag
	// mechanism (and gives double-click-to-zoom for free); the CSS class is a
	// belt-and-braces `-webkit-app-region: drag`.
	let { actions }: { actions?: Snippet } = $props();
</script>

<div data-tauri-drag-region class="drag flex h-11 shrink-0 items-center justify-between px-4">
	<div data-tauri-drag-region class="h-full flex-1"></div>
	<div class="no-drag flex items-center gap-1">
		{@render actions?.()}
	</div>
</div>
