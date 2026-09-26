/**
 * Clean Mode: a system-wide keyboard lock (`toggle_keyboard_lock`, backed by
 * a CGEventTap in Rust — see `src-tauri/src/keyboard_lock.rs`) so the
 * keyboard can be wiped down without triggering keystrokes anywhere, paired
 * with a full-screen overlay whose "Exit Clean Mode" button is the only way
 * out. Mouse input is never touched by the lock, so that button always works.
 */
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import { api } from '$lib/api';
import { EVENTS } from '$lib/api/events';

const KEY_FLASH_MS = 220;

function errorMessage(e: unknown): string {
	return e instanceof Error ? e.message : String(e);
}

class CleanModeStore {
	active = $state(false);
	pending = $state(false);
	error = $state<string | null>(null);
	/** The most recently swallowed key's name (e.g. `KeyA`), briefly, for the keyboard-map visual. */
	lastKey = $state<string | null>(null);

	#unlisten: UnlistenFn | null = null;
	#flashTimer: ReturnType<typeof setTimeout> | null = null;

	async enter() {
		if (this.active || this.pending) return;
		this.pending = true;
		this.error = null;
		try {
			const locked = await api.toggleKeyboardLock(true);
			if (!locked) throw new Error('Keyboard lock did not engage');
			this.active = true;
			this.#unlisten = await listen<string>(EVENTS.cleanModeKey, (event) => {
				this.lastKey = event.payload;
				if (this.#flashTimer) clearTimeout(this.#flashTimer);
				this.#flashTimer = setTimeout(() => (this.lastKey = null), KEY_FLASH_MS);
			});
		} catch (e) {
			this.error = errorMessage(e);
		} finally {
			this.pending = false;
		}
	}

	/**
	 * Only gives up the overlay once the lock is confirmed released — if the
	 * unlock call fails, the overlay (and its mouse-only exit button) stays up
	 * so the user always has a way to retry, rather than being left with a
	 * silently-still-locked keyboard and nothing on screen to fix it.
	 */
	async exit() {
		if (!this.active || this.pending) return;
		this.pending = true;
		this.error = null;
		try {
			await api.toggleKeyboardLock(false);
			this.active = false;
			this.#unlisten?.();
			this.#unlisten = null;
			if (this.#flashTimer) clearTimeout(this.#flashTimer);
			this.lastKey = null;
		} catch (e) {
			this.error = `Couldn't unlock — try again. (${errorMessage(e)})`;
		} finally {
			this.pending = false;
		}
	}

	toggle() {
		return this.active ? this.exit() : this.enter();
	}
}

export const cleanMode = new CleanModeStore();
