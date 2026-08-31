import type { Mode, ScanOptions, Scope } from '$lib/types/ipc';

const KEY = 'macclean.settings.v1';

interface Persisted {
	mode: Mode;
	scope: Scope;
	extraRoots: string[];
}

function read(): Partial<Persisted> {
	if (typeof localStorage === 'undefined') return {};
	try {
		return JSON.parse(localStorage.getItem(KEY) ?? '{}') as Partial<Persisted>;
	} catch {
		return {};
	}
}

class SettingsStore {
	mode = $state<Mode>('safe');
	scope = $state<Scope>('projects');
	extraRoots = $state<string[]>([]);
	#hydrated = false;

	/** Load persisted values once (call from a component on mount). */
	hydrate() {
		if (this.#hydrated) return;
		this.#hydrated = true;
		const p = read();
		if (p.mode === 'safe' || p.mode === 'aggressive') this.mode = p.mode;
		if (p.scope === 'projects' || p.scope === 'home' || p.scope === 'fullMac') this.scope = p.scope;
		if (Array.isArray(p.extraRoots))
			this.extraRoots = p.extraRoots.filter((r) => typeof r === 'string');
	}

	persist() {
		if (typeof localStorage === 'undefined') return;
		try {
			localStorage.setItem(
				KEY,
				JSON.stringify({ mode: this.mode, scope: this.scope, extraRoots: this.extraRoots })
			);
		} catch {
			/* private mode / disabled storage — ignore */
		}
	}

	options(): ScanOptions {
		return { mode: this.mode, scope: this.scope, extraRoots: [...this.extraRoots] };
	}
}

export const settings = new SettingsStore();
