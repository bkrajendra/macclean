<script lang="ts">
	import type { Snippet } from 'svelte';
	import type { HTMLButtonAttributes } from 'svelte/elements';
	import { cn } from '$lib/utils/cn';

	type Variant = 'brand' | 'danger' | 'ghost' | 'subtle';
	type Size = 'sm' | 'md' | 'lg';

	let {
		variant = 'brand',
		size = 'md',
		class: klass = '',
		type = 'button',
		loading = false,
		children,
		...rest
	}: {
		variant?: Variant;
		size?: Size;
		class?: string;
		type?: HTMLButtonAttributes['type'];
		loading?: boolean;
		children: Snippet;
	} & HTMLButtonAttributes = $props();

	const base =
		'no-drag relative inline-flex select-none items-center justify-center gap-2 rounded-full font-semibold transition active:scale-[0.98] disabled:pointer-events-none disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/50 focus-visible:ring-offset-2 focus-visible:ring-offset-surface-2';

	const sizes: Record<Size, string> = {
		sm: 'h-8 px-3.5 text-[0.8rem]',
		md: 'h-10 px-5 text-sm',
		lg: 'h-12 px-7 text-[0.95rem]'
	};

	const variants: Record<Variant, string> = {
		brand:
			'gradient-brand text-white shadow-[0_10px_24px_-10px_rgb(124_92_252/0.7)] hover:brightness-[1.05]',
		danger:
			'gradient-danger text-white shadow-[0_10px_24px_-10px_rgb(244_63_94/0.6)] hover:brightness-[1.05]',
		ghost: 'border border-line bg-surface-2 text-ink hover:bg-surface-3',
		subtle: 'bg-brand-soft text-brand hover:brightness-[0.97]'
	};
</script>

<button
	{...rest}
	{type}
	class={cn(base, sizes[size], variants[variant], klass)}
	disabled={loading || rest.disabled}
>
	{#if loading}
		<span
			class="h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent"
			aria-hidden="true"
		></span>
	{/if}
	{@render children()}
</button>
