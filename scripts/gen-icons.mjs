#!/usr/bin/env node
/**
 * Regenerate src-tauri/icons/* from assets/icon-1024.png via `tauri icon`.
 *
 * assets/icon-1024.png is the committed icon master. assets/icon.svg is the
 * editable source: if @resvg/resvg-js is installed (`npm i -D @resvg/resvg-js`),
 * this script re-rasterises the SVG into icon-1024.png first; otherwise it just
 * re-runs `tauri icon` on the existing PNG.
 */
import { execSync } from 'node:child_process';
import fs from 'node:fs';

const PNG = 'assets/icon-1024.png';

try {
	const { Resvg } = await import('@resvg/resvg-js');
	const svg = fs.readFileSync('assets/icon.svg', 'utf8');
	const png = new Resvg(svg, {
		fitTo: { mode: 'width', value: 1024 },
		background: 'rgba(0,0,0,0)'
	})
		.render()
		.asPng();
	fs.writeFileSync(PNG, png);
	console.log(`rasterised assets/icon.svg → ${PNG}`);
} catch {
	console.log(`using existing ${PNG} (install @resvg/resvg-js to rebuild it from the SVG)`);
}

if (!fs.existsSync(PNG)) {
	console.error(`${PNG} not found`);
	process.exit(1);
}

execSync(`npx --yes @tauri-apps/cli icon ${PNG}`, { stdio: 'inherit' });
// desktop-only app — drop the mobile icon sets `tauri icon` also emits
fs.rmSync('src-tauri/icons/android', { recursive: true, force: true });
fs.rmSync('src-tauri/icons/ios', { recursive: true, force: true });
