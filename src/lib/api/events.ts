/**
 * Typed subscriptions to the `scan://*` and `cleanup://*` events emitted by
 * `src-tauri/src/commands.rs`.
 */
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import type {
	CleanupProgressPayload,
	DeleteResult,
	ScanCandidate,
	ScanError,
	ScanProgress,
	ScanStartedPayload,
	ScanSummary
} from '$lib/types/ipc';

export const EVENTS = {
	scanStarted: 'scan://started',
	scanCandidates: 'scan://candidates',
	scanProgress: 'scan://progress',
	scanError: 'scan://error',
	scanCompleted: 'scan://completed',
	cleanupProgress: 'cleanup://progress',
	cleanupCompleted: 'cleanup://completed'
} as const;

export interface ScanEventHandlers {
	onStarted?: (p: ScanStartedPayload) => void;
	onCandidates?: (batch: ScanCandidate[]) => void;
	onProgress?: (p: ScanProgress) => void;
	onError?: (e: ScanError) => void;
	onCompleted?: (s: ScanSummary) => void;
}

export interface CleanupEventHandlers {
	onProgress?: (p: CleanupProgressPayload) => void;
	onCompleted?: (r: DeleteResult) => void;
}

async function bind<T>(name: string, cb?: (payload: T) => void): Promise<UnlistenFn> {
	if (!cb) return () => {};
	return listen<T>(name, (event) => cb(event.payload));
}

/** Subscribe to every scan event. Returns an unlisten that removes them all. */
export async function subscribeScan(handlers: ScanEventHandlers): Promise<UnlistenFn> {
	const unlisteners = await Promise.all([
		bind(EVENTS.scanStarted, handlers.onStarted),
		bind(EVENTS.scanCandidates, handlers.onCandidates),
		bind(EVENTS.scanProgress, handlers.onProgress),
		bind(EVENTS.scanError, handlers.onError),
		bind(EVENTS.scanCompleted, handlers.onCompleted)
	]);
	return () => unlisteners.forEach((u) => u());
}

export async function subscribeCleanup(handlers: CleanupEventHandlers): Promise<UnlistenFn> {
	const unlisteners = await Promise.all([
		bind(EVENTS.cleanupProgress, handlers.onProgress),
		bind(EVENTS.cleanupCompleted, handlers.onCompleted)
	]);
	return () => unlisteners.forEach((u) => u());
}
