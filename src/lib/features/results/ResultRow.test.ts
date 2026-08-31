import { render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { ScanCandidate } from '$lib/types/ipc';
import ResultRow from './ResultRow.svelte';

vi.mock('$lib/api', () => ({ api: { revealInFinder: vi.fn() } }));

const candidate: ScanCandidate = {
	id: 'x1',
	path: '/Users/alice/projects/app/node_modules',
	displayPath: '~/projects/app/node_modules',
	group: '/Users/alice/projects',
	sizeBytes: 300,
	itemCount: 42,
	isDir: true,
	isSymlink: false,
	category: 'Dependencies',
	ruleLabel: 'Node modules'
};

describe('ResultRow', () => {
	it('renders the label, path, size and file count', () => {
		render(ResultRow, { props: { candidate, selected: false, onToggle: () => {} } });
		expect(screen.getByText('Node modules')).toBeInTheDocument();
		expect(screen.getByText('~/projects/app/node_modules')).toBeInTheDocument();
		expect(screen.getByText('300.0 B')).toBeInTheDocument();
		expect(screen.getByText('42')).toBeInTheDocument();
		expect(screen.getByText('Dependencies')).toBeInTheDocument();
	});

	it('toggles selection when the checkbox is clicked', async () => {
		const onToggle = vi.fn();
		render(ResultRow, { props: { candidate, selected: false, onToggle } });
		await userEvent.click(screen.getByRole('checkbox', { name: /select node modules/i }));
		expect(onToggle).toHaveBeenCalledTimes(1);
	});

	it('reflects the selected state on the checkbox', () => {
		render(ResultRow, { props: { candidate, selected: true, onToggle: () => {} } });
		expect(screen.getByRole('checkbox', { name: /select node modules/i })).toHaveAttribute(
			'aria-checked',
			'true'
		);
	});
});
