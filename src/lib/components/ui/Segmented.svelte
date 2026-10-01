<script lang="ts" generics="T extends string">
	import { cn } from '$lib/utils/cn';

	let {
		value = $bindable(),
		options,
		size = 'md',
		class: klass = ''
	}: {
		value: T;
		options: ReadonlyArray<{ value: T; label: string }>;
		size?: 'sm' | 'md';
		class?: string;
	} = $props();
</script>

<div
	role="tablist"
	class={cn(
		'no-drag relative inline-grid auto-cols-fr grid-flow-col rounded-xl border border-line bg-surface-3 p-1',
		size === 'sm' ? 'text-[0.8rem]' : 'text-sm',
		klass
	)}
>
	<span
		class="pointer-events-none absolute bottom-1 left-1 top-1 rounded-lg bg-surface-2 shadow-tile transition-transform duration-200 ease-in-out"
		style="width: calc((100% - 0.5rem) / {options.length}); transform: translateX({Math.max(
			0,
			options.findIndex((o) => o.value === value)
		) * 100}%)"
		aria-hidden="true"
	></span>
	{#each options as opt (opt.value)}
		<button
			role="tab"
			type="button"
			aria-selected={value === opt.value}
			onclick={() => (value = opt.value)}
			class={cn(
				'relative rounded-lg px-3.5 font-semibold transition active:scale-[0.97]',
				size === 'sm' ? 'h-7' : 'h-8',
				value === opt.value ? 'text-ink' : 'text-muted hover:text-ink'
			)}
		>
			{opt.label}
		</button>
	{/each}
</div>
