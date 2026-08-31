/** Byte formatter matching the Rust `rules::human_size` (1 dp, 1024 steps). */
export function formatBytes(bytes: number): string {
	let size = Math.max(0, bytes);
	for (const unit of ['B', 'KB', 'MB', 'GB']) {
		if (size < 1024) return `${size.toFixed(1)} ${unit}`;
		size /= 1024;
	}
	return `${size.toFixed(1)} TB`;
}

/** Compact byte formatter for tight spots: "2.6 GB", "812 MB", "0 B". */
export function formatBytesCompact(bytes: number): string {
	let size = Math.max(0, bytes);
	const units = ['B', 'KB', 'MB', 'GB', 'TB'];
	let i = 0;
	while (size >= 1024 && i < units.length - 1) {
		size /= 1024;
		i += 1;
	}
	const digits = size < 10 && i > 0 ? 1 : 0;
	return `${size.toFixed(digits)} ${units[i]}`;
}

export function formatCount(n: number): string {
	return Math.round(n).toLocaleString('en-US');
}

/** "00:01:24" — always HH:MM:SS. */
export function formatDuration(ms: number): string {
	const total = Math.max(0, Math.floor(ms / 1000));
	const h = Math.floor(total / 3600);
	const m = Math.floor((total % 3600) / 60);
	const s = total % 60;
	const pad = (v: number) => String(v).padStart(2, '0');
	return `${pad(h)}:${pad(m)}:${pad(s)}`;
}

export function formatPercent(fraction: number): string {
	return `${Math.round(clamp(fraction, 0, 1) * 100)}%`;
}

export function clamp(v: number, min: number, max: number): number {
	return Math.min(max, Math.max(min, v));
}

/** `~`-shorten an absolute path given the user's home directory. */
export function shortenPath(path: string, home: string): string {
	if (!home) return path;
	if (path === home) return '~';
	if (path.startsWith(home + '/')) return '~' + path.slice(home.length);
	return path;
}

/** Trim a long path for display, keeping the head and tail. */
export function truncateMiddle(text: string, max = 64): string {
	if (text.length <= max) return text;
	const keep = Math.floor((max - 1) / 2);
	return `${text.slice(0, keep)}…${text.slice(-keep)}`;
}
