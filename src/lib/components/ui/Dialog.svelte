<script lang="ts">
	import { X } from '@lucide/svelte';
	import type { Snippet } from 'svelte';
	import { cn } from '$lib/utils/cn';

	let {
		open = $bindable(false),
		title,
		description,
		size = 'md',
		dismissible = true,
		onclose,
		children,
		footer
	}: {
		open?: boolean;
		title: string;
		description?: string;
		size?: 'sm' | 'md' | 'lg';
		dismissible?: boolean;
		onclose?: () => void;
		children: Snippet;
		footer?: Snippet;
	} = $props();

	function close() {
		if (!dismissible) return;
		open = false;
		onclose?.();
	}

	function onkeydown(e: KeyboardEvent) {
		if (open && e.key === 'Escape') close();
	}

	const widths = { sm: 'max-w-sm', md: 'max-w-lg', lg: 'max-w-2xl' } as const;
</script>

<svelte:window {onkeydown} />

{#if open}
	<div class="fixed inset-0 z-50 flex items-center justify-center p-6">
		<button
			type="button"
			aria-label="Close"
			tabindex="-1"
			class="absolute inset-0 animate-fade-in bg-ink/25 backdrop-blur-[3px] dark:bg-black/50"
			onclick={close}
		></button>

		<div
			role="dialog"
			aria-modal="true"
			aria-label={title}
			class={cn(
				'card relative w-full animate-scale-in overflow-hidden p-0 shadow-pop',
				widths[size]
			)}
		>
			<header class="flex items-start justify-between gap-4 border-b border-line px-6 pb-4 pt-5">
				<div class="min-w-0">
					<h2 class="font-display text-lg font-bold text-ink">{title}</h2>
					{#if description}
						<p class="mt-0.5 text-sm text-muted">{description}</p>
					{/if}
				</div>
				{#if dismissible}
					<button
						type="button"
						aria-label="Close"
						class="-mr-1 -mt-1 grid h-8 w-8 place-items-center rounded-lg text-muted transition hover:bg-surface-3 hover:text-ink"
						onclick={close}
					>
						<X class="h-4 w-4" />
					</button>
				{/if}
			</header>

			<div class="max-h-[68vh] overflow-y-auto px-6 py-5">
				{@render children()}
			</div>

			{#if footer}
				<footer
					class="flex items-center justify-end gap-3 border-t border-line bg-surface-3/60 px-6 py-4"
				>
					{@render footer()}
				</footer>
			{/if}
		</div>
	</div>
{/if}
