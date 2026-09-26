/**
 * Light/dark theme preference. 'system' (the default) tracks the OS live;
 * 'light'/'dark' pin it regardless of the OS. The only consumer of this
 * store's `effective` value is `+layout.svelte`, which mirrors it onto
 * `<html data-theme>` — everything else (Tailwind's `dark:` utilities, the
 * CSS custom properties in app.css) reacts to that attribute, not to this
 * store directly.
 */
export type ThemePreference = 'system' | 'light' | 'dark';

const KEY = 'macclean.theme.v1';

function systemPrefersDark(): boolean {
	return typeof matchMedia !== 'undefined' && matchMedia('(prefers-color-scheme: dark)').matches;
}

class ThemeStore {
	preference = $state<ThemePreference>('system');
	#systemDark = $state(systemPrefersDark());
	#hydrated = false;

	get effective(): 'light' | 'dark' {
		return this.preference === 'system' ? (this.#systemDark ? 'dark' : 'light') : this.preference;
	}

	/** Load the persisted preference and start tracking the OS, once. Call from a component on mount. */
	hydrate() {
		if (this.#hydrated) return;
		this.#hydrated = true;

		if (typeof localStorage !== 'undefined') {
			try {
				const saved = localStorage.getItem(KEY);
				if (saved === 'light' || saved === 'dark' || saved === 'system') this.preference = saved;
			} catch {
				/* private mode / disabled storage — ignore */
			}
		}

		if (typeof matchMedia !== 'undefined') {
			const mql = matchMedia('(prefers-color-scheme: dark)');
			this.#systemDark = mql.matches;
			mql.addEventListener('change', (e) => (this.#systemDark = e.matches));
		}
	}

	set(pref: ThemePreference) {
		this.preference = pref;
		if (typeof localStorage === 'undefined') return;
		try {
			localStorage.setItem(KEY, pref);
		} catch {
			/* private mode / disabled storage — ignore */
		}
	}

	/** System → Light → Dark → System. */
	cycle() {
		this.set(
			this.preference === 'system' ? 'light' : this.preference === 'light' ? 'dark' : 'system'
		);
	}
}

export const theme = new ThemeStore();
