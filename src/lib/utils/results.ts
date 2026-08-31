/** Pure filter / sort / rollup helpers for scan results (fully unit-tested). */
import type { Category, ScanCandidate } from '$lib/types/ipc';

export type SortKey = 'sizeDesc' | 'sizeAsc' | 'countDesc' | 'pathAsc' | 'pathDesc';

export const SORT_OPTIONS: Array<{ value: SortKey; label: string }> = [
	{ value: 'sizeDesc', label: 'Largest first' },
	{ value: 'sizeAsc', label: 'Smallest first' },
	{ value: 'countDesc', label: 'Most files first' },
	{ value: 'pathAsc', label: 'Path A–Z' },
	{ value: 'pathDesc', label: 'Path Z–A' }
];

export interface ResultsFilter {
	search: string;
	category: Category | 'all';
	group: string | 'all';
	sort: SortKey;
}

export const EMPTY_FILTER: ResultsFilter = {
	search: '',
	category: 'all',
	group: 'all',
	sort: 'sizeDesc'
};

function matchesSearch(c: ScanCandidate, q: string): boolean {
	if (!q) return true;
	const needle = q.toLowerCase();
	return (
		c.path.toLowerCase().includes(needle) ||
		c.displayPath.toLowerCase().includes(needle) ||
		c.ruleLabel.toLowerCase().includes(needle) ||
		c.category.toLowerCase().includes(needle) ||
		c.group.toLowerCase().includes(needle)
	);
}

export function filterCandidates(items: ScanCandidate[], f: ResultsFilter): ScanCandidate[] {
	return items.filter(
		(c) =>
			(f.category === 'all' || c.category === f.category) &&
			(f.group === 'all' || c.group === f.group) &&
			matchesSearch(c, f.search)
	);
}

export function sortCandidates(items: ScanCandidate[], sort: SortKey): ScanCandidate[] {
	const out = [...items];
	out.sort((a, b) => {
		switch (sort) {
			case 'sizeAsc':
				return a.sizeBytes - b.sizeBytes || a.displayPath.localeCompare(b.displayPath);
			case 'countDesc':
				return b.itemCount - a.itemCount || b.sizeBytes - a.sizeBytes;
			case 'pathAsc':
				return a.displayPath.localeCompare(b.displayPath);
			case 'pathDesc':
				return b.displayPath.localeCompare(a.displayPath);
			case 'sizeDesc':
			default:
				return b.sizeBytes - a.sizeBytes || a.displayPath.localeCompare(b.displayPath);
		}
	});
	return out;
}

export function filterSortCandidates(items: ScanCandidate[], f: ResultsFilter): ScanCandidate[] {
	return sortCandidates(filterCandidates(items, f), f.sort);
}

export interface Bucket<T extends string> {
	key: T;
	count: number;
	bytes: number;
}

/** Per-category totals, sorted by reclaimable bytes descending. */
export function categoryBuckets(items: ScanCandidate[]): Bucket<Category>[] {
	const map = new Map<Category, Bucket<Category>>();
	for (const c of items) {
		const b = map.get(c.category) ?? { key: c.category, count: 0, bytes: 0 };
		b.count += 1;
		b.bytes += c.sizeBytes;
		map.set(c.category, b);
	}
	return [...map.values()].sort((a, b) => b.bytes - a.bytes || b.count - a.count);
}

/** Per-group (location) totals, sorted by bytes descending. */
export function groupBuckets(items: ScanCandidate[]): Bucket<string>[] {
	const map = new Map<string, Bucket<string>>();
	for (const c of items) {
		const b = map.get(c.group) ?? { key: c.group, count: 0, bytes: 0 };
		b.count += 1;
		b.bytes += c.sizeBytes;
		map.set(c.group, b);
	}
	return [...map.values()].sort((a, b) => b.bytes - a.bytes);
}

export function sumBytes(items: ScanCandidate[]): number {
	return items.reduce((acc, c) => acc + c.sizeBytes, 0);
}

/** Totals for a selection given a lookup map (O(selected), not O(all)). */
export function selectionTotals(
	ids: Iterable<string>,
	byId: Map<string, ScanCandidate>
): { count: number; bytes: number } {
	let count = 0;
	let bytes = 0;
	for (const id of ids) {
		const c = byId.get(id);
		if (c) {
			count += 1;
			bytes += c.sizeBytes;
		}
	}
	return { count, bytes };
}
