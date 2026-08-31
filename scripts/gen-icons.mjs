#!/usr/bin/env node
/**
 * Rasterise assets/icon.svg → assets/icon-1024.png, then run `tauri icon` to
 * regenerate src-tauri/icons/*. Run after editing the SVG:  `npm run icons`.
 *
 * @resvg/resvg-js is NOT a project dependency (its platform packages destabilise
 * the lockfile and it is only needed for this occasional task). Install it
 * on demand:  `npm i -D @resvg/resvg-js`  — or just run `npx @tauri-apps/cli
 * icon <your-1024.png>` directly.
 */
import { execSync } from 'node:child_process';
import fs from 'node:fs';

let Resvg;
try {
	({ Resvg } = await import('@resvg/resvg-js'));
} catch {
	console.error(
		'@resvg/resvg-js is not installed. Run:  npm i -D @resvg/resvg-js\n' +
			'(then `npm uninstall @resvg/resvg-js` again — keep it out of the committed lock).'
	);
	process.exit(1);
}

const svg = fs.readFileSync('assets/icon.svg', 'utf8');
const png = new Resvg(svg, { fitTo: { mode: 'width', value: 1024 }, background: 'rgba(0,0,0,0)' })
	.render()
	.asPng();

fs.writeFileSync('assets/icon-1024.png', png);
console.log('wrote assets/icon-1024.png');

execSync('npx --yes @tauri-apps/cli icon assets/icon-1024.png', { stdio: 'inherit' });
