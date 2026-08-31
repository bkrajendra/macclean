import { api } from '$lib/api';
import type { PermissionStatus, SystemInfo } from '$lib/types/ipc';

class SystemStore {
	info = $state<SystemInfo | null>(null);
	permissions = $state<PermissionStatus | null>(null);
	loading = $state(false);
	error = $state<string | null>(null);

	get home(): string {
		return this.info?.homeDir ?? '';
	}

	async load() {
		this.loading = true;
		this.error = null;
		try {
			const [info, permissions] = await Promise.all([
				api.getSystemInfo(),
				api.getPermissionStatus()
			]);
			this.info = info;
			this.permissions = permissions;
		} catch (e) {
			this.error = String(e);
		} finally {
			this.loading = false;
		}
	}

	async refreshPermissions() {
		try {
			this.permissions = await api.getPermissionStatus();
		} catch (e) {
			this.error = String(e);
		}
	}
}

export const system = new SystemStore();
