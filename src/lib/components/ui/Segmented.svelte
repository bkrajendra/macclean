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
		'no-drag inline-flex rounded-xl border border-line bg-surface-3 p-1',
		size === 'sm' ? 'text-[0.8rem]' : 'text-sm',
		klass
	)}
>
	{#each options as opt (opt.value)}
		<button
			role="tab"
			type="button"
			aria-selected={value === opt.value}
			onclick={() => (value = opt.value)}
			class={cn(
				'rounded-lg px-3.5 font-semibold transition',
				size === 'sm' ? 'h-7' : 'h-8',
				value === opt.value ? 'bg-surface-2 text-ink shadow-tile' : 'text-muted hover:text-ink'
			)}
		>
			{opt.label}
		</button>
	{/each}
</div>
