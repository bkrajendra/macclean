<script lang="ts">
	import { chipFor } from '$lib/constants/categories';
	import type { Category } from '$lib/types/ipc';
	import { cn } from '$lib/utils/cn';

	let { category, class: klass = '' }: { category: Category; class?: string } = $props();
	const chip = $derived(chipFor(category));
</script>

<span
	class={cn(
		'inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[0.7rem] font-semibold',
		chip.bg,
		chip.fg,
		klass
	)}
>
	<span class="h-1.5 w-1.5 rounded-full {chip.dot}"></span>
	{category}
</span>
