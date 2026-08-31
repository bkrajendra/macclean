/**
 * TypeScript mirror of `src-tauri/crates/macclean-core/src/model.rs`.
 * Keep in sync with the Rust `#[derive(Serialize)]` types.
 */

export type Mode = 'safe' | 'aggressive';

export type Scope = 'projects' | 'home' | 'fullMac';

export type Category =
	| 'Dependencies'
	| 'Python'
	| 'Frontend'
	| 'Caches'
	| 'Build'
	| 'Testing'
	| 'Infrastructure'
	| 'macOS'
	| 'System cache'
	| 'Browser cache'
	| 'Logs'
	| 'Developer tools'
	| 'Package manager cache'
	| 'Other';

export interface ScanOptions {
	mode: Mode;
	scope: Scope;
	extraRoots: string[];
}

export interface ScanCandidate {
	id: string;
	path: string;
	displayPath: string;
	group: string;
	sizeBytes: number;
	itemCount: number;
	isDir: boolean;
	isSymlink: boolean;
	category: Category;
	ruleLabel: string;
}

export type ScanState = 'idle' | 'scanning' | 'completed' | 'cancelled' | 'failed';

export type ScanErrorKind = 'permissionDenied' | 'notFound' | 'io';

export interface ScanError {
	path: string;
	kind: ScanErrorKind;
	message: string;
}

export interface ScanProgress {
	scanId: string;
	state: ScanState;
	scannedDirs: number;
	currentDir: string;
	itemsFound: number;
	bytesFound: number;
	errors: number;
}

export interface CategorySummary {
	category: Category;
	count: number;
	bytes: number;
}

export interface GroupSummary {
	group: string;
	displayGroup: string;
	count: number;
	bytes: number;
}

export interface ScanSummary {
	scanId: string;
	mode: Mode;
	scope: Scope;
	state: ScanState;
	roots: string[];
	totalBytes: number;
	totalCount: number;
	scannedDirs: number;
	categories: CategorySummary[];
	groups: GroupSummary[];
	errors: ScanError[];
	permissionDeniedCount: number;
	isAdmin: boolean;
	startedAtMs: number;
	finishedAtMs: number;
}

export interface DeleteRequest {
	scanId: string;
	candidateIds: string[];
}

export type DeleteStatus =
	| 'deleted'
	| 'skipped'
	| 'failed'
	| 'permissionDenied'
	| 'alreadyMissing'
	| 'protected'
	| 'notInSession'
	| 'changed';

export interface DeleteOutcome {
	id: string;
	path: string;
	displayPath: string;
	status: DeleteStatus;
	freedBytes: number;
	message: string | null;
}

export interface DeleteResult {
	scanId: string;
	invalidScanId: boolean;
	outcomes: DeleteOutcome[];
	deletedCount: number;
	deletedBytes: number;
	skippedCount: number;
	failedCount: number;
}

export interface PermissionProbe {
	label: string;
	path: string;
	readable: boolean;
}

export interface PermissionStatus {
	fullDiskAccess: boolean;
	homeReadable: boolean;
	probes: PermissionProbe[];
}

export interface SystemInfo {
	platform: string;
	arch: string;
	currentUser: string;
	isAdmin: boolean;
	homeDir: string;
	projectsDir: string;
	totalDiskBytes: number;
	availableDiskBytes: number;
	appVersion: string;
}

export interface RuleInfo {
	key: string;
	kind: string;
	label: string;
	category: Category;
	safe: boolean;
	aggressive: boolean;
	scope: string;
}

export interface ScopeDescriptor {
	value: Scope;
	label: string;
	description: string;
}

/* ---- event payloads (src-tauri/src/events.rs) ---- */

export interface ScanStartedPayload {
	scanId: string;
	roots: string[];
}

export interface CleanupProgressPayload {
	scanId: string;
	done: number;
	total: number;
	freedBytes: number;
	lastPath: string;
	lastStatus: DeleteStatus;
}
