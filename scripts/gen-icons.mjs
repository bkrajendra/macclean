#!/usr/bin/env node
/**
 * Rasterise assets/icon.svg → assets/icon-1024.png, then run `tauri icon` to
 * regenerate src-tauri/icons/*. Run after editing the SVG:  `npm run icons`.
 */
import { execSync } from 'node:child_process';
import fs from 'node:fs';
import { Resvg } from '@resvg/resvg-js';

const svg = fs.readFileSync('assets/icon.svg', 'utf8');
const png = new Resvg(svg, { fitTo: { mode: 'width', value: 1024 }, background: 'rgba(0,0,0,0)' })
	.render()
	.asPng();

fs.writeFileSync('assets/icon-1024.png', png);
console.log('wrote assets/icon-1024.png');

execSync('npx --yes @tauri-apps/cli icon assets/icon-1024.png', { stdio: 'inherit' });
