import { api } from '$lib/api';
import type { PermissionStatus, SystemInfo } from '$lib/types/ipc';

class SystemStore {
	info = $state<SystemInfo | null>(null);
	permissions = $state<PermissionStatus | null>(null);
	/** Accessibility access, which Clean Mode's keyboard lock needs — independent of Full Disk Access. */
	accessibility = $state<boolean | null>(null);
	loading = $state(false);
	error = $state<string | null>(null);

	get home(): string {
		return this.info?.homeDir ?? '';
	}

	async load() {
		this.loading = true;
		this.error = null;
		try {
			const [info, permissions, accessibility] = await Promise.all([
				api.getSystemInfo(),
				api.getPermissionStatus(),
				api.getAccessibilityStatus()
			]);
			this.info = info;
			this.permissions = permissions;
			this.accessibility = accessibility;
		} catch (e) {
			this.error = String(e);
		} finally {
			this.loading = false;
		}
	}

	async refreshPermissions() {
		try {
			const [permissions, accessibility] = await Promise.all([
				api.getPermissionStatus(),
				api.getAccessibilityStatus()
			]);
			this.permissions = permissions;
			this.accessibility = accessibility;
		} catch (e) {
			this.error = String(e);
		}
	}
}

export const system = new SystemStore();
