import { flushSync } from 'svelte';
import { render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ScanCandidate, ScanSummary } from '$lib/types/ipc';
import type { ScanEventHandlers } from '$lib/api/events';

const hoisted = vi.hoisted(() => ({
	scanHandlers: {} as ScanEventHandlers,
	api: { startScan: vi.fn(async () => 's1'), deleteSelected: vi.fn(), cancelScan: vi.fn() }
}));
vi.mock('$lib/api', () => ({ api: hoisted.api }));
vi.mock('$lib/api/events', () => ({
	EVENTS: {},
	subscribeScan: vi.fn(async (h: ScanEventHandlers) => {
		hoisted.scanHandlers = h;
		return () => {};
	}),
	subscribeCleanup: vi.fn(async () => () => {})
}));

const { scan } = await import('$lib/stores/scan.svelte');
const ConfirmCleanupDialog = (await import('./ConfirmCleanupDialog.svelte')).default;

function cand(id: string, bytes: number): ScanCandidate {
	return {
		id,
		path: `/Users/alice/${id}`,
		displayPath: `~/${id}`,
		group: '/Users/alice/projects',
		sizeBytes: bytes,
		itemCount: 1,
		isDir: true,
		isSymlink: false,
		category: 'Caches',
		ruleLabel: `Cache ${id}`
	};
}
const summary: ScanSummary = {
	scanId: 's1',
	mode: 'safe',
	scope: 'projects',
	state: 'completed',
	roots: [],
	totalBytes: 3072,
	totalCount: 2,
	scannedDirs: 1,
	categories: [],
	groups: [],
	errors: [],
	permissionDeniedCount: 0,
	isAdmin: false,
	startedAtMs: 0,
	finishedAtMs: 1
};

beforeEach(async () => {
	await scan.reset();
	await scan.start({ mode: 'safe', scope: 'projects', extraRoots: [] });
	hoisted.scanHandlers.onCandidates?.([cand('a', 2048), cand('b', 1024)]);
	hoisted.scanHandlers.onCompleted?.(summary);
	flushSync();
});
afterEach(() => vi.clearAllMocks());

describe('ConfirmCleanupDialog', () => {
	it('summarises the selection and warns about permanence', () => {
		render(ConfirmCleanupDialog, { props: { open: true, onconfirm: () => {} } });
		expect(screen.getByText('Delete 2 items?')).toBeInTheDocument();
		expect(screen.getByText(/permanently/i)).toBeInTheDocument();
		expect(screen.getByText('3.0 KB', { exact: false })).toBeInTheDocument();
	});

	it('fires onconfirm and closes on the delete button', async () => {
		const onconfirm = vi.fn();
		render(ConfirmCleanupDialog, { props: { open: true, onconfirm } });
		await userEvent.click(screen.getByRole('button', { name: /delete 2 items/i }));
		expect(onconfirm).toHaveBeenCalledTimes(1);
	});

	it('cancel does not confirm', async () => {
		const onconfirm = vi.fn();
		render(ConfirmCleanupDialog, { props: { open: true, onconfirm } });
		await userEvent.click(screen.getByRole('button', { name: /^cancel$/i }));
		expect(onconfirm).not.toHaveBeenCalled();
	});
});
