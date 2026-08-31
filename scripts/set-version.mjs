#!/usr/bin/env node
/** Write a semantic version into package.json, tauri.conf.json and the two
 *  Cargo.toml `[package]` sections. Usage: `node scripts/set-version.mjs X.Y.Z`
 *  Output stays tab-indented to match .prettierrc (`useTabs: true`). */
import fs from 'node:fs';

const version = process.argv[2];
if (!/^\d+\.\d+\.\d+$/.test(version ?? '')) {
	console.error('usage: node scripts/set-version.mjs <major.minor.patch>');
	process.exit(1);
}

// Bump the top-level `version` key of a JSON file in place, preserving key
// order and tab indentation.
function bumpJsonVersion(path) {
	const raw = fs.readFileSync(path, 'utf8');
	const bumped = raw.replace(/("version"\s*:\s*)"[^"]*"/, `$1"${version}"`);
	if (bumped === raw) throw new Error(`no "version" key found in ${path}`);
	fs.writeFileSync(path, bumped);
}

bumpJsonVersion('package.json');
bumpJsonVersion('src-tauri/tauri.conf.json');

// Cargo.toml — replace only the first `version = "..."` (the [package] one)
for (const path of ['src-tauri/Cargo.toml', 'src-tauri/crates/macclean-core/Cargo.toml']) {
	const src = fs.readFileSync(path, 'utf8');
	fs.writeFileSync(path, src.replace(/^version = ".*"$/m, `version = "${version}"`));
}

console.log(`version set to ${version}`);
