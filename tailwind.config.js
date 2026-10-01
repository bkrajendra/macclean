import forms from '@tailwindcss/forms';

/** @type {import('tailwindcss').Config} */
export default {
	future: { hoverOnlyWhenSupported: true },
	content: ['./src/**/*.{html,js,svelte,ts}'],
	// Manual override via `<html data-theme="dark">` (see lib/stores/theme.svelte.ts),
	// not just the OS preference — 'system' mode sets this attribute to match
	// prefers-color-scheme itself, so `dark:` utilities still track the OS by
	// default; this just adds a way to override it.
	darkMode: ['selector', '[data-theme="dark"]'],
	theme: {
		extend: {
			colors: {
				surface: 'rgb(var(--surface) / <alpha-value>)',
				'surface-2': 'rgb(var(--surface-2) / <alpha-value>)',
				'surface-3': 'rgb(var(--surface-3) / <alpha-value>)',
				ink: 'rgb(var(--ink) / <alpha-value>)',
				muted: 'rgb(var(--muted) / <alpha-value>)',
				faint: 'rgb(var(--faint) / <alpha-value>)',
				line: 'rgb(var(--line) / <alpha-value>)',
				brand: 'rgb(var(--brand) / <alpha-value>)',
				'brand-2': 'rgb(var(--brand-2) / <alpha-value>)',
				'brand-soft': 'rgb(var(--brand-soft) / <alpha-value>)',
				danger: 'rgb(var(--danger) / <alpha-value>)',
				'danger-2': 'rgb(var(--danger-2) / <alpha-value>)',
				ok: 'rgb(var(--ok) / <alpha-value>)',
				warn: 'rgb(var(--warn) / <alpha-value>)'
			},
			fontFamily: {
				sans: [
					'-apple-system',
					'BlinkMacSystemFont',
					'"SF Pro Text"',
					'"Segoe UI"',
					'system-ui',
					'sans-serif'
				],
				display: [
					'"SF Pro Rounded"',
					'ui-rounded',
					'-apple-system',
					'BlinkMacSystemFont',
					'"Segoe UI"',
					'system-ui',
					'sans-serif'
				],
				mono: ['ui-monospace', '"SF Mono"', '"JetBrains Mono"', 'Menlo', 'monospace']
			},
			transitionTimingFunction: {
				out: 'var(--ease-out)',
				'in-out': 'var(--ease-in-out)'
			},
			borderRadius: {
				xl2: '1.25rem',
				xl3: '1.75rem'
			},
			boxShadow: {
				card: '0 1px 2px rgb(20 18 45 / 0.04), 0 10px 30px -16px rgb(20 18 45 / 0.16)',
				tile: '0 1px 2px rgb(20 18 45 / 0.04)',
				pop: '0 24px 70px -24px rgb(20 18 45 / 0.4)'
			},
			keyframes: {
				'fade-in': { from: { opacity: '0' }, to: { opacity: '1' } },
				'scale-in': {
					from: { opacity: '0', transform: 'scale(0.96)' },
					to: { opacity: '1', transform: 'scale(1)' }
				},
				'slide-up': {
					from: { opacity: '0', transform: 'translateY(8px)' },
					to: { opacity: '1', transform: 'translateY(0)' }
				},
				'pop-in': {
					from: { opacity: '0', transform: 'scale(0.6)' },
					to: { opacity: '1', transform: 'scale(1)' }
				},
				orbit: { to: { transform: 'rotate(360deg)' } },
				'pulse-ring': {
					'0%': { transform: 'scale(0.6)', opacity: '0.8' },
					'100%': { transform: 'scale(1.15)', opacity: '0' }
				}
			},
			animation: {
				'fade-in': 'fade-in 0.18s var(--ease-out)',
				'scale-in': 'scale-in 0.2s var(--ease-out)',
				'slide-up': 'slide-up 0.22s var(--ease-out)',
				'screen-in': 'slide-up 0.22s var(--ease-out)',
				'pop-in': 'pop-in 0.28s var(--ease-out) backwards',
				orbit: 'orbit 22s linear infinite',
				'orbit-rev': 'orbit 30s linear infinite reverse',
				'pulse-ring': 'pulse-ring 2.4s ease-out infinite'
			}
		}
	},
	plugins: [forms]
};
