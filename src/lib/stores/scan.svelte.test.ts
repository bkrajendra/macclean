import { flushSync } from 'svelte';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { DeleteResult, ScanCandidate, ScanOptions, ScanSummary } from '$lib/types/ipc';
import type { CleanupEventHandlers, ScanEventHandlers } from '$lib/api/events';

const hoisted = vi.hoisted(() => ({
	scanHandlers: {} as ScanEventHandlers,
	cleanupHandlers: {} as CleanupEventHandlers,
	api: {
		startScan: vi.fn(async (_o: ScanOptions) => 'scan-1'),
		cancelScan: vi.fn(async () => true),
		getScanProgress: vi.fn(async () => null),
		deleteSelected: vi.fn(async (): Promise<DeleteResult> => emptyResult())
	}
}));

vi.mock('$lib/api', () => ({ api: hoisted.api }));
vi.mock('$lib/api/events', () => ({
	EVENTS: {},
	subscribeScan: vi.fn(async (h: ScanEventHandlers) => {
		hoisted.scanHandlers = h;
		return () => {};
	}),
	subscribeCleanup: vi.fn(async (h: CleanupEventHandlers) => {
		hoisted.cleanupHandlers = h;
		return () => {};
	})
}));

const { scan } = await import('./scan.svelte');

function emptyResult(): DeleteResult {
	return {
		scanId: 'scan-1',
		invalidScanId: false,
		outcomes: [],
		deletedCount: 0,
		deletedBytes: 0,
		skippedCount: 0,
		failedCount: 0
	};
}

function cand(
	id: string,
	sizeBytes: number,
	category: ScanCandidate['category'] = 'Caches'
): ScanCandidate {
	return {
		id,
		path: `/Users/alice/${id}`,
		displayPath: `~/${id}`,
		group: '/Users/alice/projects',
		sizeBytes,
		itemCount: 3,
		isDir: true,
		isSymlink: false,
		category,
		ruleLabel: 'Generic cache folder'
	};
}

function summary(over: Partial<ScanSummary> = {}): ScanSummary {
	return {
		scanId: 'scan-1',
		mode: 'safe',
		scope: 'projects',
		state: 'completed',
		roots: ['/Users/alice/projects'],
		totalBytes: 300,
		totalCount: 2,
		scannedDirs: 12,
		categories: [],
		groups: [],
		errors: [],
		permissionDeniedCount: 0,
		isAdmin: false,
		startedAtMs: 0,
		finishedAtMs: 1000,
		...over
	};
}

const OPTS: ScanOptions = { mode: 'safe', scope: 'projects', extraRoots: [] };

beforeEach(async () => {
	await scan.reset();
	hoisted.api.startScan.mockClear();
	hoisted.api.cancelScan.mockClear();
	hoisted.api.deleteSelected.mockClear();
});

describe('scan store — lifecycle', () => {
	it('starts idle', () => {
		expect(scan.phase).toBe('idle');
		expect(scan.candidates).toHaveLength(0);
	});

	it('start() moves to scanning and calls the backend', async () => {
		await scan.start(OPTS);
		flushSync();
		expect(scan.phase).toBe('scanning');
		expect(hoisted.api.startScan).toHaveBeenCalledWith(OPTS);
	});

	it('streams candidates and auto-selects them', async () => {
		await scan.start(OPTS);
		hoisted.scanHandlers.onStarted?.({ scanId: 'scan-1', roots: ['/Users/alice/projects'] });
		hoisted.scanHandlers.onCandidates?.([cand('a', 200), cand('b', 100)]);
		flushSync();

		expect(scan.candidates).toHaveLength(2);
		expect(scan.selectedCount).toBe(2);
		expect(scan.selectedBytes).toBe(300);
	});

	it('completes into the results phase with a summary', async () => {
		await scan.start(OPTS);
		hoisted.scanHandlers.onCandidates?.([cand('a', 200), cand('b', 100)]);
		hoisted.scanHandlers.onCompleted?.(summary());
		flushSync();

		expect(scan.phase).toBe('results');
		expect(scan.summary?.scanId).toBe('scan-1');
		expect(scan.totalBytes).toBe(300);
		expect(scan.totalCount).toBe(2);
	});

	it('cancel() asks the backend to stop; a cancelled summary still lands in results', async () => {
		await scan.start(OPTS);
		hoisted.scanHandlers.onStarted?.({ scanId: 'scan-1', roots: [] });
		hoisted.scanHandlers.onCandidates?.([cand('a', 200)]);
		await scan.cancel();
		expect(hoisted.api.cancelScan).toHaveBeenCalledWith('scan-1');

		hoisted.scanHandlers.onCompleted?.(
			summary({ state: 'cancelled', totalCount: 1, totalBytes: 200 })
		);
		flushSync();
		expect(scan.phase).toBe('results');
		expect(scan.summary?.state).toBe('cancelled');
		expect(scan.candidates).toHaveLength(1);
	});
});

describe('scan store — selection & filtering', () => {
	beforeEach(async () => {
		await scan.start(OPTS);
		hoisted.scanHandlers.onCandidates?.([
			cand('a', 300, 'Dependencies'),
			cand('b', 100, 'Caches'),
			cand('c', 200, 'Caches')
		]);
		hoisted.scanHandlers.onCompleted?.(summary({ totalCount: 3, totalBytes: 600 }));
		flushSync();
	});

	it('toggle removes/adds a single id', () => {
		scan.toggle('a');
		flushSync();
		expect(scan.selectedIds.has('a')).toBe(false);
		expect(scan.selectedCount).toBe(2);
		scan.toggle('a');
		flushSync();
		expect(scan.selectedCount).toBe(3);
	});

	it('selectNone / selectAll', () => {
		scan.selectNone();
		flushSync();
		expect(scan.selectedCount).toBe(0);
		scan.selectAll();
		flushSync();
		expect(scan.selectedCount).toBe(3);
	});

	it('category filter drives the visible list', () => {
		scan.filterCategory = 'Caches';
		flushSync();
		expect(scan.visible.map((c) => c.id).sort()).toEqual(['b', 'c']);
		scan.sortKey = 'sizeDesc';
		flushSync();
		expect(scan.visible.map((c) => c.id)).toEqual(['c', 'b']);
	});

	it('deselectAllVisible only clears the filtered set', () => {
		scan.filterCategory = 'Caches';
		flushSync();
		scan.deselectAllVisible();
		flushSync();
		expect(scan.selectedIds.has('a')).toBe(true);
		expect(scan.selectedIds.has('b')).toBe(false);
		expect(scan.selectedCount).toBe(1);
	});
});

describe('scan store — cleanup', () => {
	beforeEach(async () => {
		await scan.start(OPTS);
		hoisted.scanHandlers.onCandidates?.([cand('a', 300), cand('b', 100)]);
		hoisted.scanHandlers.onCompleted?.(summary({ totalCount: 2, totalBytes: 400 }));
		flushSync();
	});

	it('clean() deletes the selection, prunes candidates and shows the summary', async () => {
		hoisted.api.deleteSelected.mockResolvedValueOnce({
			scanId: 'scan-1',
			invalidScanId: false,
			outcomes: [
				{
					id: 'a',
					path: '/Users/alice/a',
					displayPath: '~/a',
					status: 'deleted',
					freedBytes: 300,
					message: null
				},
				{
					id: 'b',
					path: '/Users/alice/b',
					displayPath: '~/b',
					status: 'deleted',
					freedBytes: 100,
					message: null
				}
			],
			deletedCount: 2,
			deletedBytes: 400,
			skippedCount: 0,
			failedCount: 0
		});

		await scan.clean();
		flushSync();

		expect(hoisted.api.deleteSelected).toHaveBeenCalledWith({
			scanId: 'scan-1',
			candidateIds: expect.arrayContaining(['a', 'b'])
		});
		expect(scan.phase).toBe('summary');
		expect(scan.cleanupResult?.deletedCount).toBe(2);
		expect(scan.candidates).toHaveLength(0);
		expect(scan.selectedCount).toBe(0);
	});

	it('keeps un-deleted candidates when only some are removed', async () => {
		scan.selectNone();
		scan.select('a');
		flushSync();
		hoisted.api.deleteSelected.mockResolvedValueOnce({
			scanId: 'scan-1',
			invalidScanId: false,
			outcomes: [
				{ id: 'a', path: '', displayPath: '~/a', status: 'deleted', freedBytes: 300, message: null }
			],
			deletedCount: 1,
			deletedBytes: 300,
			skippedCount: 0,
			failedCount: 0
		});

		await scan.clean();
		flushSync();
		expect(scan.candidates.map((c) => c.id)).toEqual(['b']);
		expect(scan.phase).toBe('summary');
	});

	it('backToResults returns to the list', async () => {
		hoisted.api.deleteSelected.mockResolvedValueOnce({
			scanId: 'scan-1',
			invalidScanId: false,
			outcomes: [
				{ id: 'a', path: '', displayPath: '', status: 'deleted', freedBytes: 300, message: null }
			],
			deletedCount: 1,
			deletedBytes: 300,
			skippedCount: 0,
			failedCount: 0
		});
		await scan.clean();
		flushSync();
		scan.backToResults();
		flushSync();
		expect(scan.phase).toBe('results');
	});
});
