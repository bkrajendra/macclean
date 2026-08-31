#!/usr/bin/env node
/** Write a semantic version into package.json, tauri.conf.json and the two
 *  Cargo.toml `[package]` sections. Usage: `node scripts/set-version.mjs X.Y.Z` */
import fs from 'node:fs';

const version = process.argv[2];
if (!/^\d+\.\d+\.\d+$/.test(version ?? '')) {
	console.error('usage: node scripts/set-version.mjs <major.minor.patch>');
	process.exit(1);
}

// package.json
const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
pkg.version = version;
fs.writeFileSync('package.json', JSON.stringify(pkg, null, '\t') + '\n');

// src-tauri/tauri.conf.json
const conf = JSON.parse(fs.readFileSync('src-tauri/tauri.conf.json', 'utf8'));
conf.version = version;
fs.writeFileSync('src-tauri/tauri.conf.json', JSON.stringify(conf, null, 2) + '\n');

// Cargo.toml — replace only the first `version = "..."` (the [package] one)
for (const path of ['src-tauri/Cargo.toml', 'src-tauri/crates/macclean-core/Cargo.toml']) {
	const src = fs.readFileSync(path, 'utf8');
	fs.writeFileSync(path, src.replace(/^version = ".*"$/m, `version = "${version}"`));
}

console.log(`version set to ${version}`);
