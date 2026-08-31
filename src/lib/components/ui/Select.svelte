<script lang="ts" generics="T extends string">
	import { ChevronDown } from '@lucide/svelte';
	import type { Snippet } from 'svelte';
	import { cn } from '$lib/utils/cn';

	let {
		value = $bindable(),
		options,
		disabled = false,
		class: klass = '',
		leading,
		ariaLabel
	}: {
		value: T;
		options: ReadonlyArray<{ value: T; label: string }>;
		disabled?: boolean;
		class?: string;
		leading?: Snippet;
		ariaLabel?: string;
	} = $props();
</script>

<div
	class={cn(
		'no-drag relative flex h-10 items-center gap-2 rounded-xl border border-line bg-surface-2 px-3 text-sm font-medium text-ink transition focus-within:border-brand/60 focus-within:ring-2 focus-within:ring-brand/25',
		disabled && 'opacity-50',
		klass
	)}
>
	{#if leading}
		<span class="text-brand">{@render leading()}</span>
	{/if}
	<select
		bind:value
		{disabled}
		aria-label={ariaLabel}
		class="peer w-full appearance-none border-0 bg-transparent p-0 pr-5 text-sm font-medium text-ink focus:outline-none focus:ring-0"
	>
		{#each options as opt (opt.value)}
			<option value={opt.value}>{opt.label}</option>
		{/each}
	</select>
	<ChevronDown class="pointer-events-none absolute right-3 h-4 w-4 text-faint" />
</div>
