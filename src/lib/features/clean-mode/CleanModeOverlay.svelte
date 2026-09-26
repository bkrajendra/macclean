<script lang="ts">
	import { KeyboardOff, ShieldAlert, TriangleAlert } from '@lucide/svelte';
	import Button from '$lib/components/ui/Button.svelte';
	import KeyboardMap from './KeyboardMap.svelte';
	import { cleanMode } from '$lib/stores/cleanMode.svelte';
</script>

{#if cleanMode.active}
	<div
		class="fixed inset-0 z-[100] flex flex-col items-center justify-center gap-8 overflow-y-auto bg-[#0a0916] px-6 py-10 text-center"
		style="background-image: radial-gradient(120% 70% at 50% -10%, rgb(124 92 252 / 0.22), transparent 60%);"
	>
		<div class="flex flex-col items-center gap-4">
			<span
				class="grid h-16 w-16 place-items-center rounded-full bg-white/[0.06] text-white/80 shadow-[0_0_40px_-4px_rgb(168_85_247/0.5)]"
			>
				<KeyboardOff class="h-8 w-8" />
			</span>
			<h1 class="font-display text-3xl font-extrabold tracking-tight text-white sm:text-4xl">
				Clean Mode Active
			</h1>
			<p class="max-w-md text-balance text-sm text-white/60 sm:text-base">
				Wipe down your keyboard safely — every key is locked system-wide, even
				<span class="text-white/80">⌘Q</span> and <span class="text-white/80">⌘Tab</span>. Only your
				mouse works while Clean Mode is on.
			</p>
		</div>

		<KeyboardMap activeKey={cleanMode.lastKey} />

		<div class="flex flex-col items-center gap-3">
			{#if cleanMode.error}
				<p
					class="flex max-w-md items-center gap-2 text-balance rounded-lg bg-rose-500/10 px-3 py-2 text-xs text-rose-300"
				>
					<TriangleAlert class="h-4 w-4 shrink-0" />
					{cleanMode.error}
				</p>
			{/if}
			<Button
				variant="brand"
				size="lg"
				class="h-16 min-w-[16rem] text-base shadow-[0_20px_50px_-12px_rgb(168_85_247/0.7)]"
				loading={cleanMode.pending}
				onclick={() => cleanMode.exit()}
			>
				Exit Clean Mode
			</Button>
			<p class="flex items-center gap-1.5 text-xs text-white/40">
				<ShieldAlert class="h-3.5 w-3.5" /> Click above — keyboard shortcuts won't work here.
			</p>
		</div>
	</div>
{/if}
