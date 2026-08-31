import type { Category } from '$lib/types/ipc';
import {
	Boxes,
	Braces,
	Bug,
	Globe,
	CloudCog,
	Database,
	FileCode2,
	FolderCog,
	HardDrive,
	Layers,
	Package,
	ScrollText,
	Wrench,
	type LucideIcon
} from '@lucide/svelte';

export interface CategoryMeta {
	/** deterministic accent index into the chip palette */
	accent: number;
	icon: LucideIcon;
	/** short label for tight UI (sidebar) */
	short: string;
}

/**
 * Maps every engine [`Category`] to a chip accent + icon. Content follows the
 * spec (the real engine categories); the visual treatment follows the mockups.
 */
export const CATEGORY_META: Record<Category, CategoryMeta> = {
	'System cache': { accent: 0, icon: FolderCog, short: 'System cache' },
	'Browser cache': { accent: 1, icon: Globe, short: 'Browser cache' },
	'Package manager cache': { accent: 2, icon: Package, short: 'Package caches' },
	Dependencies: { accent: 3, icon: Boxes, short: 'Dependencies' },
	'Developer tools': { accent: 4, icon: Wrench, short: 'Developer tools' },
	Frontend: { accent: 5, icon: Layers, short: 'Frontend' },
	Python: { accent: 6, icon: Braces, short: 'Python' },
	Build: { accent: 7, icon: FileCode2, short: 'Build output' },
	Testing: { accent: 1, icon: Bug, short: 'Testing' },
	Infrastructure: { accent: 2, icon: CloudCog, short: 'Infrastructure' },
	Caches: { accent: 0, icon: Database, short: 'Caches' },
	Logs: { accent: 4, icon: ScrollText, short: 'Logs' },
	macOS: { accent: 5, icon: HardDrive, short: 'macOS' },
	Other: { accent: 3, icon: Database, short: 'Other' }
};

/** Chip palette (bg / text) — bright, always dark-text-on-light-chip. */
export const CHIP_PALETTE: Array<{ bg: string; fg: string; dot: string }> = [
	{
		bg: 'bg-violet-100 dark:bg-violet-500/15',
		fg: 'text-violet-700 dark:text-violet-300',
		dot: 'bg-violet-500'
	},
	{
		bg: 'bg-pink-100 dark:bg-pink-500/15',
		fg: 'text-pink-700 dark:text-pink-300',
		dot: 'bg-pink-500'
	},
	{ bg: 'bg-sky-100 dark:bg-sky-500/15', fg: 'text-sky-700 dark:text-sky-300', dot: 'bg-sky-500' },
	{
		bg: 'bg-emerald-100 dark:bg-emerald-500/15',
		fg: 'text-emerald-700 dark:text-emerald-300',
		dot: 'bg-emerald-500'
	},
	{
		bg: 'bg-amber-100 dark:bg-amber-500/15',
		fg: 'text-amber-700 dark:text-amber-300',
		dot: 'bg-amber-500'
	},
	{
		bg: 'bg-indigo-100 dark:bg-indigo-500/15',
		fg: 'text-indigo-700 dark:text-indigo-300',
		dot: 'bg-indigo-500'
	},
	{
		bg: 'bg-rose-100 dark:bg-rose-500/15',
		fg: 'text-rose-700 dark:text-rose-300',
		dot: 'bg-rose-500'
	},
	{
		bg: 'bg-teal-100 dark:bg-teal-500/15',
		fg: 'text-teal-700 dark:text-teal-300',
		dot: 'bg-teal-500'
	}
];

export function chipFor(category: Category) {
	return CHIP_PALETTE[(CATEGORY_META[category]?.accent ?? 0) % CHIP_PALETTE.length];
}

export function iconFor(category: Category) {
	return CATEGORY_META[category]?.icon ?? Database;
}
