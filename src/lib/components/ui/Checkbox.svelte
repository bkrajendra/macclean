<script lang="ts">
	import { Check, Minus } from '@lucide/svelte';
	import { cn } from '$lib/utils/cn';

	let {
		checked = false,
		indeterminate = false,
		disabled = false,
		label,
		class: klass = '',
		onchange
	}: {
		checked?: boolean;
		indeterminate?: boolean;
		disabled?: boolean;
		label: string;
		class?: string;
		onchange?: (checked: boolean) => void;
	} = $props();
</script>

<button
	type="button"
	role="checkbox"
	aria-checked={indeterminate ? 'mixed' : checked}
	aria-label={label}
	{disabled}
	onclick={() => onchange?.(!checked)}
	class={cn(
		'no-drag grid h-[18px] w-[18px] shrink-0 place-items-center rounded-[6px] border transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/50 focus-visible:ring-offset-1 focus-visible:ring-offset-surface-2',
		checked || indeterminate
			? 'gradient-brand border-transparent text-white'
			: 'border-line bg-surface-2 hover:border-brand/50',
		disabled && 'cursor-not-allowed opacity-40',
		klass
	)}
>
	{#if indeterminate}
		<Minus class="h-3 w-3" stroke-width={3} />
	{:else if checked}
		<Check class="h-3 w-3" stroke-width={3.5} />
	{/if}
</button>
