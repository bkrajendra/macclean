import type { ScopeDescriptor } from '$lib/types/ipc';

/** Fallback used when the backend `list_scopes` command is unreachable
 *  (e.g. `vite dev` outside the Tauri shell). Mirrors `scope::describe`. */
export const FALLBACK_SCOPES: ScopeDescriptor[] = [
	{ value: 'projects', label: 'Projects', description: 'Scan only ~/projects' },
	{
		value: 'home',
		label: 'User home',
		description: 'Scan your home folder and user-level caches'
	},
	{
		value: 'fullMac',
		label: 'Full Mac',
		description: 'Scan user homes plus system cache locations'
	}
];
