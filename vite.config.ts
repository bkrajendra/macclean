import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

// @ts-expect-error process is a nodejs global
const host = process.env.TAURI_DEV_HOST;

// Vite options tailored for Tauri: https://v2.tauri.app/start/frontend/sveltekit/
export default defineConfig({
	plugins: [sveltekit()],
	// Prevent Vite from clearing Rust compiler errors.
	clearScreen: false,
	server: {
		port: 1420,
		strictPort: true,
		host: host || false,
		hmr: host ? { protocol: 'ws', host, port: 1421 } : undefined,
		watch: { ignored: ['**/src-tauri/**'] }
	}
});
