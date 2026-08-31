import { describe, expect, it } from 'vitest';
import type { Category, ScanCandidate } from '$lib/types/ipc';
import {
	categoryBuckets,
	EMPTY_FILTER,
	filterCandidates,
	filterSortCandidates,
	groupBuckets,
	selectionTotals,
	sortCandidates
} from './results';

function cand(p: Partial<ScanCandidate> & { id: string }): ScanCandidate {
	return {
		id: p.id,
		path: p.path ?? `/Users/alice/${p.id}`,
		displayPath: p.displayPath ?? `~/${p.id}`,
		group: p.group ?? '/Users/alice/projects',
		sizeBytes: p.sizeBytes ?? 100,
		itemCount: p.itemCount ?? 1,
		isDir: p.isDir ?? true,
		isSymlink: p.isSymlink ?? false,
		category: p.category ?? 'Caches',
		ruleLabel: p.ruleLabel ?? 'Generic cache folder'
	};
}

const items: ScanCandidate[] = [
	cand({
		id: 'a',
		sizeBytes: 300,
		itemCount: 9,
		category: 'Dependencies',
		ruleLabel: 'Node modules',
		group: '/Users/alice/projects',
		displayPath: '~/projects/app/node_modules'
	}),
	cand({
		id: 'b',
		sizeBytes: 100,
		itemCount: 2,
		category: 'Caches',
		ruleLabel: 'User app cache',
		group: '/Users/alice/Library',
		displayPath: '~/Library/Caches/x'
	}),
	cand({
		id: 'c',
		sizeBytes: 200,
		itemCount: 40,
		category: 'Caches',
		ruleLabel: 'pip cache',
		group: '/Users/alice/Library',
		displayPath: '~/Library/Caches/pip'
	}),
	cand({
		id: 'd',
		sizeBytes: 50,
		itemCount: 1,
		category: 'Logs',
		ruleLabel: 'User logs',
		group: '/Users/alice/Library',
		displayPath: '~/Library/Logs/app.log'
	})
];

describe('filterCandidates', () => {
	it('no filter keeps everything', () => {
		expect(filterCandidates(items, EMPTY_FILTER)).toHaveLength(4);
	});
	it('filters by category', () => {
		const r = filterCandidates(items, { ...EMPTY_FILTER, category: 'Caches' as Category });
		expect(r.map((c) => c.id).sort()).toEqual(['b', 'c']);
	});
	it('filters by group', () => {
		const r = filterCandidates(items, { ...EMPTY_FILTER, group: '/Users/alice/projects' });
		expect(r.map((c) => c.id)).toEqual(['a']);
	});
	it('search matches path, label and category, case-insensitively', () => {
		expect(filterCandidates(items, { ...EMPTY_FILTER, search: 'PIP' }).map((c) => c.id)).toEqual([
			'c'
		]);
		expect(
			filterCandidates(items, { ...EMPTY_FILTER, search: 'node_modules' }).map((c) => c.id)
		).toEqual(['a']);
		expect(filterCandidates(items, { ...EMPTY_FILTER, search: 'logs' }).map((c) => c.id)).toEqual([
			'd'
		]);
	});
});

describe('sortCandidates', () => {
	it('sizeDesc (default) then sizeAsc', () => {
		expect(sortCandidates(items, 'sizeDesc').map((c) => c.id)).toEqual(['a', 'c', 'b', 'd']);
		expect(sortCandidates(items, 'sizeAsc').map((c) => c.id)).toEqual(['d', 'b', 'c', 'a']);
	});
	it('countDesc by file count', () => {
		expect(sortCandidates(items, 'countDesc').map((c) => c.id)).toEqual(['c', 'a', 'b', 'd']);
	});
	it('path A-Z / Z-A (by displayPath)', () => {
		// ~/Library/Caches/pip < ~/Library/Caches/x < ~/Library/Logs/app.log < ~/projects/...
		expect(sortCandidates(items, 'pathAsc').map((c) => c.id)).toEqual(['c', 'b', 'd', 'a']);
		expect(sortCandidates(items, 'pathDesc').map((c) => c.id)).toEqual(['a', 'd', 'b', 'c']);
	});
	it('does not mutate the input', () => {
		const before = items.map((c) => c.id);
		sortCandidates(items, 'sizeAsc');
		expect(items.map((c) => c.id)).toEqual(before);
	});
});

describe('filterSortCandidates', () => {
	it('composes filter then sort', () => {
		const r = filterSortCandidates(items, {
			...EMPTY_FILTER,
			category: 'Caches' as Category,
			sort: 'sizeAsc'
		});
		expect(r.map((c) => c.id)).toEqual(['b', 'c']);
	});
});

describe('rollups', () => {
	it('categoryBuckets sorted by bytes desc', () => {
		const b = categoryBuckets(items);
		expect(b.map((x) => x.key)).toEqual(['Caches', 'Dependencies', 'Logs']);
		expect(b[0]).toMatchObject({ key: 'Caches', count: 2, bytes: 300 });
	});
	it('groupBuckets sorted by bytes desc', () => {
		const b = groupBuckets(items);
		expect(b[0].key).toBe('/Users/alice/Library');
		expect(b[0].bytes).toBe(350);
	});
});

describe('selectionTotals', () => {
	it('sums only known ids', () => {
		const byId = new Map(items.map((c) => [c.id, c]));
		expect(selectionTotals(['a', 'd', 'ghost'], byId)).toEqual({ count: 2, bytes: 350 });
		expect(selectionTotals([], byId)).toEqual({ count: 0, bytes: 0 });
	});
});
