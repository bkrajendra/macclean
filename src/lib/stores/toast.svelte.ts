export type ToastKind = 'info' | 'success' | 'warning' | 'error';

export interface Toast {
	id: number;
	kind: ToastKind;
	title: string;
	detail?: string;
}

class ToastStore {
	items = $state<Toast[]>([]);
	#seq = 0;

	push(kind: ToastKind, title: string, detail?: string, ttl = 5000) {
		const id = ++this.#seq;
		this.items = [...this.items, { id, kind, title, detail }];
		if (ttl > 0) setTimeout(() => this.dismiss(id), ttl);
		return id;
	}

	info = (t: string, d?: string) => this.push('info', t, d);
	success = (t: string, d?: string) => this.push('success', t, d);
	warning = (t: string, d?: string) => this.push('warning', t, d, 8000);
	error = (t: string, d?: string) => this.push('error', t, d, 9000);

	dismiss(id: number) {
		this.items = this.items.filter((t) => t.id !== id);
	}
}

export const toasts = new ToastStore();
