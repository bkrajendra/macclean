import { SvelteSet } from 'svelte/reactivity';
import type { UnlistenFn } from '@tauri-apps/api/event';
import { api } from '$lib/api';
import { subscribeCleanup, subscribeScan } from '$lib/api/events';
import type {
	Category,
	CleanupProgressPayload,
	DeleteResult,
	ScanCandidate,
	ScanError,
	ScanOptions,
	ScanProgress,
	ScanSummary
} from '$lib/types/ipc';
import {
	categoryBuckets,
	EMPTY_FILTER,
	filterSortCandidates,
	groupBuckets,
	sumBytes,
	type ResultsFilter,
	type SortKey
} from '$lib/utils/results';

export type Phase = 'idle' | 'scanning' | 'results' | 'cleaning' | 'summary';

class ScanStore {
	phase = $state<Phase>('idle');
	scanId = $state<string | null>(null);
	fatal = $state<string | null>(null);

	// --- scanning ---
	candidates = $state<ScanCandidate[]>([]);
	progress = $state<ScanProgress | null>(null);
	errors = $state<ScanError[]>([]);
	roots = $state<string[]>([]);
	startedAt = $state(0);
	cancelling = $state(false);

	// --- results ---
	summary = $state<ScanSummary | null>(null);
	search = $state('');
	filterCategory = $state<Category | 'all'>('all');
	filterGroup = $state<string | 'all'>('all');
	sortKey = $state<SortKey>('sizeDesc');
	selectedIds = new SvelteSet<string>();

	// --- cleaning / summary ---
	cleanupProgress = $state<CleanupProgressPayload | null>(null);
	cleanupResult = $state<DeleteResult | null>(null);

	#unlistenScan: UnlistenFn | null = null;
	#unlistenCleanup: UnlistenFn | null = null;

	// ---- derived ----
	get filter(): ResultsFilter {
		return {
			search: this.search,
			category: this.filterCategory,
			group: this.filterGroup,
			sort: this.sortKey
		};
	}

	visible = $derived.by(() => filterSortCandidates(this.candidates, this.filter));
	byCategory = $derived.by(() => categoryBuckets(this.candidates));
	byGroup = $derived.by(() => groupBuckets(this.candidates));

	selectedItems = $derived.by(() => this.candidates.filter((c) => this.selectedIds.has(c.id)));
	selectedBytes = $derived.by(() => sumBytes(this.selectedItems));
	selectedCount = $derived.by(() => this.selectedItems.length);

	totalBytes = $derived.by(
		() => this.summary?.totalBytes ?? this.progress?.bytesFound ?? sumBytes(this.candidates)
	);
	totalCount = $derived.by(() => this.summary?.totalCount ?? this.candidates.length);

	allVisibleSelected = $derived.by(() => {
		const v = this.visible;
		return v.length > 0 && v.every((c) => this.selectedIds.has(c.id));
	});

	// ---- lifecycle ----
	async start(options: ScanOptions) {
		await this.#teardown();
		this.phase = 'scanning';
		this.scanId = null;
		this.fatal = null;
		this.cancelling = false;
		this.candidates = [];
		this.progress = null;
		this.errors = [];
		this.roots = [];
		this.summary = null;
		this.cleanupProgress = null;
		this.cleanupResult = null;
		this.selectedIds.clear();
		this.filterCategory = 'all';
		this.filterGroup = 'all';
		this.search = '';
		this.sortKey = EMPTY_FILTER.sort;
		this.startedAt = Date.now();

		this.#unlistenScan = await subscribeScan({
			onStarted: (p) => {
				this.scanId = p.scanId;
				this.roots = p.roots;
			},
			onCandidates: (batch) => {
				this.candidates = this.candidates.concat(batch);
				for (const c of batch) this.selectedIds.add(c.id);
			},
			onProgress: (p) => {
				this.progress = p;
			},
			onError: (e) => {
				this.errors = [...this.errors, e].slice(-500);
			},
			onCompleted: (s) => this.#finishScan(s)
		});

		try {
			this.scanId = await api.startScan(options);
		} catch (e) {
			this.fatal = String(e);
			this.phase = 'idle';
			await this.#teardown();
		}
	}

	async cancel() {
		if (!this.scanId || this.phase !== 'scanning') return;
		this.cancelling = true;
		try {
			await api.cancelScan(this.scanId);
		} catch {
			/* the completed event still arrives */
		}
	}

	#finishScan(summary: ScanSummary) {
		this.summary = summary;
		this.progress = {
			scanId: summary.scanId,
			state: summary.state,
			scannedDirs: summary.scannedDirs,
			currentDir: '',
			itemsFound: summary.totalCount,
			bytesFound: summary.totalBytes,
			errors: summary.errors.length
		};
		this.cancelling = false;
		this.phase = 'results';
	}

	// ---- selection ----
	toggle(id: string) {
		if (this.selectedIds.has(id)) this.selectedIds.delete(id);
		else this.selectedIds.add(id);
	}
	select(id: string) {
		this.selectedIds.add(id);
	}
	deselect(id: string) {
		this.selectedIds.delete(id);
	}
	selectAllVisible() {
		for (const c of this.visible) this.selectedIds.add(c.id);
	}
	deselectAllVisible() {
		for (const c of this.visible) this.selectedIds.delete(c.id);
	}
	selectAll() {
		for (const c of this.candidates) this.selectedIds.add(c.id);
	}
	selectNone() {
		this.selectedIds.clear();
	}

	// ---- cleanup ----
	async clean() {
		const ids = this.selectedItems.map((c) => c.id);
		if (!this.scanId || ids.length === 0) return;
		await this.#teardownCleanup();
		this.phase = 'cleaning';
		this.cleanupResult = null;
		this.cleanupProgress = {
			scanId: this.scanId,
			done: 0,
			total: ids.length,
			freedBytes: 0,
			lastPath: '',
			lastStatus: 'skipped'
		};

		this.#unlistenCleanup = await subscribeCleanup({
			onProgress: (p) => {
				this.cleanupProgress = p;
			}
		});

		try {
			const result = await api.deleteSelected({ scanId: this.scanId, candidateIds: ids });
			this.#applyCleanup(result);
		} catch (e) {
			this.fatal = String(e);
			this.phase = 'results';
			await this.#teardownCleanup();
		}
	}

	#applyCleanup(result: DeleteResult) {
		this.cleanupResult = result;
		const gone = new Set(
			result.outcomes
				.filter((o) => o.status === 'deleted' || o.status === 'alreadyMissing')
				.map((o) => o.id)
		);
		this.candidates = this.candidates.filter((c) => !gone.has(c.id));
		for (const id of gone) this.selectedIds.delete(id);
		this.phase = 'summary';
		void this.#teardownCleanup();
	}

	backToResults() {
		this.cleanupResult = null;
		this.cleanupProgress = null;
		this.phase = this.candidates.length > 0 ? 'results' : 'idle';
	}

	async reset() {
		await this.#teardown();
		this.phase = 'idle';
		this.scanId = null;
		this.candidates = [];
		this.progress = null;
		this.errors = [];
		this.summary = null;
		this.cleanupResult = null;
		this.cleanupProgress = null;
		this.selectedIds.clear();
	}

	async dispose() {
		await this.#teardown();
	}

	async #teardownCleanup() {
		this.#unlistenCleanup?.();
		this.#unlistenCleanup = null;
	}

	async #teardown() {
		this.#unlistenScan?.();
		this.#unlistenScan = null;
		await this.#teardownCleanup();
	}
}

export const scan = new ScanStore();
