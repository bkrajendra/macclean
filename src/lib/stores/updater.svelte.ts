/**
 * Checks the `latest.json` manifest published alongside each GitHub Release
 * (see `scripts/updater-manifest.mjs` and `tauri.conf.json`'s `plugins.updater`)
 * and, once the user asks, downloads + installs that update and relaunches.
 */
import { check, type Update } from '@tauri-apps/plugin-updater';
import { relaunch } from '@tauri-apps/plugin-process';

function errorMessage(e: unknown): string {
	return e instanceof Error ? e.message : String(e);
}

class UpdaterStore {
	checking = $state(false);
	installing = $state(false);
	/** 0–100, or null before the download reports a content length. */
	progress = $state<number | null>(null);
	error = $state<string | null>(null);
	#update = $state<Update | null>(null);

	get available() {
		return this.#update !== null;
	}
	get version() {
		return this.#update?.version ?? null;
	}
	get notes() {
		return this.#update?.body ?? null;
	}

	/** Best-effort background check — never surfaces an error banner for something like being offline. */
	async checkForUpdate() {
		if (this.checking || this.installing) return;
		this.checking = true;
		try {
			this.#update = await check();
		} catch {
			this.#update = null;
		} finally {
			this.checking = false;
		}
	}

	async install() {
		const update = this.#update;
		if (!update || this.installing) return;
		this.installing = true;
		this.error = null;
		let total = 0;
		let downloaded = 0;
		try {
			await update.downloadAndInstall((event) => {
				if (event.event === 'Started') {
					total = event.data.contentLength ?? 0;
				} else if (event.event === 'Progress') {
					downloaded += event.data.chunkLength;
					this.progress = total > 0 ? Math.round((downloaded / total) * 100) : null;
				}
			});
			await relaunch();
		} catch (e) {
			this.error = errorMessage(e);
			this.installing = false;
		}
	}
}

export const updater = new UpdaterStore();
