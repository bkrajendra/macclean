#!/usr/bin/env node
/** Write a semantic version into package.json, tauri.conf.json and the two
 *  Cargo.toml `[package]` sections. Usage: `node scripts/set-version.mjs X.Y.Z` */
import { stampVersion } from './lib/versioning.mjs';

const version = process.argv[2];
try {
	stampVersion(version);
} catch (e) {
	console.error(`usage: node scripts/set-version.mjs <major.minor.patch>\n${e.message}`);
	process.exit(1);
}

console.log(`version set to ${version}`);
