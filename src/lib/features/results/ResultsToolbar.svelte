<script lang="ts">
	import { Search } from '@lucide/svelte';
	import Checkbox from '$lib/components/ui/Checkbox.svelte';
	import Select from '$lib/components/ui/Select.svelte';
	import { SORT_OPTIONS, type SortKey } from '$lib/utils/results';
	import { formatBytesCompact, formatCount } from '$lib/utils/format';
	import { scan } from '$lib/stores/scan.svelte';

	const someVisibleSelected = $derived(
		scan.visible.some((c) => scan.selectedIds.has(c.id)) && !scan.allVisibleSelected
	);

	function toggleAll() {
		if (scan.allVisibleSelected) scan.deselectAllVisible();
		else scan.selectAllVisible();
	}

	const sortOptions = SORT_OPTIONS as ReadonlyArray<{ value: SortKey; label: string }>;
</script>

<div class="flex flex-wrap items-center gap-3 border-b border-line px-4 py-3">
	<Checkbox
		checked={scan.allVisibleSelected}
		indeterminate={someVisibleSelected}
		onchange={toggleAll}
		label="Select all visible"
	/>
	<div class="mr-auto">
		<p class="text-sm font-semibold text-ink">
			{scan.filterCategory === 'all' ? 'All items' : scan.filterCategory}
		</p>
		<p class="text-xs text-muted">
			{formatCount(scan.selectedCount)} selected · {formatBytesCompact(scan.selectedBytes)}
			<span class="text-faint">· {formatCount(scan.visible.length)} shown</span>
		</p>
	</div>

	<label class="relative">
		<Search
			class="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-faint"
		/>
		<input
			type="search"
			placeholder="Search path or label"
			bind:value={scan.search}
			class="h-9 w-52 rounded-xl border border-line bg-surface-2 pl-9 pr-3 text-sm text-ink placeholder:text-faint focus:border-brand/60 focus:outline-none focus:ring-2 focus:ring-brand/25"
		/>
	</label>

	<Select bind:value={scan.sortKey} options={sortOptions} ariaLabel="Sort results" class="w-40" />
</div>

<div
	class="flex items-center gap-3 px-[1.4rem] py-2 text-[0.68rem] font-semibold uppercase tracking-wide text-faint"
>
	<span class="flex-1">Name</span>
	<span class="w-20 text-right">Size</span>
	<span class="hidden w-16 text-right lg:block">Files</span>
	<span class="hidden w-32 text-right xl:block">Location</span>
	<span class="w-8"></span>
</div>
