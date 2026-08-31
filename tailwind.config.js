import forms from '@tailwindcss/forms';

/** @type {import('tailwindcss').Config} */
export default {
	content: ['./src/**/*.{html,js,svelte,ts}'],
	darkMode: 'media',
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
				orbit: { to: { transform: 'rotate(360deg)' } },
				'pulse-ring': {
					'0%': { transform: 'scale(0.6)', opacity: '0.8' },
					'100%': { transform: 'scale(1.15)', opacity: '0' }
				}
			},
			animation: {
				'fade-in': 'fade-in 0.2s ease-out',
				'scale-in': 'scale-in 0.16s cubic-bezier(0.2, 1.2, 0.4, 1)',
				'slide-up': 'slide-up 0.24s ease-out',
				orbit: 'orbit 22s linear infinite',
				'orbit-rev': 'orbit 30s linear infinite reverse',
				'pulse-ring': 'pulse-ring 2.4s ease-out infinite'
			}
		}
	},
	plugins: [forms]
};
