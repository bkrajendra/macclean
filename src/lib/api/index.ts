/**
 * Typed wrappers over the Tauri IPC commands (`src-tauri/src/commands.rs`).
 * The frontend never touches the filesystem — it can only ask for a scan,
 * cancel one, poll progress, or delete candidate *ids* from a session.
 */
import { invoke } from '@tauri-apps/api/core';
import type {
	DeleteRequest,
	DeleteResult,
	PermissionStatus,
	RuleInfo,
	ScanOptions,
	ScanProgress,
	ScopeDescriptor,
	SystemInfo
} from '$lib/types/ipc';

export const api = {
	getSystemInfo: () => invoke<SystemInfo>('get_system_info'),
	getPermissionStatus: () => invoke<PermissionStatus>('get_permission_status'),
	getRules: () => invoke<RuleInfo[]>('get_rules'),
	listScopes: () => invoke<ScopeDescriptor[]>('list_scopes'),

	startScan: (options: ScanOptions) => invoke<string>('start_scan', { options }),
	cancelScan: (scanId: string) => invoke<boolean>('cancel_scan', { scanId }),
	getScanProgress: (scanId: string) => invoke<ScanProgress | null>('get_scan_progress', { scanId }),

	deleteSelected: (request: DeleteRequest) => invoke<DeleteResult>('delete_selected', { request }),

	revealInFinder: (path: string) => invoke<void>('reveal_in_finder', { path }),
	openPrivacySettings: () => invoke<void>('open_privacy_settings'),
	restartApp: () => invoke<void>('restart_app')
};
