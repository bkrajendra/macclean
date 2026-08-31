import { describe, expect, it } from 'vitest';
import {
	clamp,
	formatBytes,
	formatBytesCompact,
	formatCount,
	formatDuration,
	formatPercent,
	shortenPath,
	truncateMiddle
} from './format';

describe('formatBytes (matches Rust human_size)', () => {
	it('formats each unit with one decimal', () => {
		expect(formatBytes(0)).toBe('0.0 B');
		expect(formatBytes(512)).toBe('512.0 B');
		expect(formatBytes(1024)).toBe('1.0 KB');
		expect(formatBytes(1536)).toBe('1.5 KB');
		expect(formatBytes(1024 ** 2)).toBe('1.0 MB');
		expect(formatBytes(1024 ** 3)).toBe('1.0 GB');
		expect(formatBytes(5 * 1024 ** 4)).toBe('5.0 TB');
	});
	it('never goes negative', () => {
		expect(formatBytes(-10)).toBe('0.0 B');
	});
});

describe('formatBytesCompact', () => {
	it('drops decimals for whole units and large values', () => {
		expect(formatBytesCompact(0)).toBe('0 B');
		expect(formatBytesCompact(2 * 1024 ** 3 + 600 * 1024 ** 2)).toBe('2.6 GB');
		expect(formatBytesCompact(812 * 1024 ** 2)).toBe('812 MB');
	});
});

describe('formatCount', () => {
	it('adds thousands separators', () => {
		expect(formatCount(1248)).toBe('1,248');
		expect(formatCount(0)).toBe('0');
		expect(formatCount(1000000)).toBe('1,000,000');
	});
});

describe('formatDuration', () => {
	it('always renders HH:MM:SS', () => {
		expect(formatDuration(0)).toBe('00:00:00');
		expect(formatDuration(84_000)).toBe('00:01:24');
		expect(formatDuration(3_661_000)).toBe('01:01:01');
	});
});

describe('formatPercent / clamp', () => {
	it('clamps and rounds', () => {
		expect(formatPercent(0)).toBe('0%');
		expect(formatPercent(0.426)).toBe('43%');
		expect(formatPercent(2)).toBe('100%');
		expect(clamp(5, 0, 3)).toBe(3);
	});
});

describe('shortenPath', () => {
	const home = '/Users/alice';
	it('collapses the home prefix to ~', () => {
		expect(shortenPath('/Users/alice', home)).toBe('~');
		expect(shortenPath('/Users/alice/Library/Caches', home)).toBe('~/Library/Caches');
		expect(shortenPath('/Library/Caches/foo', home)).toBe('/Library/Caches/foo');
		expect(shortenPath('/Users/alicia/x', home)).toBe('/Users/alicia/x');
	});
});

describe('truncateMiddle', () => {
	it('keeps head and tail', () => {
		expect(truncateMiddle('short', 20)).toBe('short');
		const t = truncateMiddle('/Users/alice/projects/very/deep/node_modules/pkg', 25);
		expect(t.length).toBeLessThanOrEqual(25);
		expect(t).toContain('…');
	});
});
