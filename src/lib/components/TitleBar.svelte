<script lang="ts">
	import { getCurrentWindow } from '@tauri-apps/api/window';
	import type { Snippet } from 'svelte';

	// macOS overlay title bar: the traffic lights are drawn natively over the
	// content, so we only reserve a draggable strip and host right-aligned
	// window-level actions. Double-click zooms the window (standard macOS).
	let { actions }: { actions?: Snippet } = $props();

	async function zoom() {
		try {
			await getCurrentWindow().toggleMaximize();
		} catch {
			/* not running inside the Tauri shell */
		}
	}
</script>

<!-- svelte-ignore a11y_no_static_element_interactions -->
<div
	class="drag flex h-11 shrink-0 items-center justify-between px-4"
	role="presentation"
	ondblclick={zoom}
>
	<div class="h-full w-24"></div>
	<div class="no-drag flex items-center gap-1">
		{@render actions?.()}
	</div>
</div>
