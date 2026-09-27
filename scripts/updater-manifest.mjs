#!/usr/bin/env node
/**
 * Assembles `latest.json` — the manifest `src-tauri/tauri.conf.json`'s
 * `plugins.updater.endpoints` points at — from the `.app.tar.gz` + `.sig`
 * that `tauri build` produces when `bundle.createUpdaterArtifacts` is true.
 * Also copies the tarball into the output dir under a stable, versioned name
 * matching the URL this script writes into the manifest.
 *
 * Run after the build, from the repo root:
 *   node scripts/updater-manifest.mjs <version> <bundleDir> <outDir>
 *
 *   <bundleDir>  e.g. src-tauri/target/universal-apple-darwin/release/bundle
 *   <outDir>     e.g. dist-artifacts — gh release create uploads everything here
 *
 * The signature is identical for both platform keys below on purpose: this
 * is a universal binary, so the same .app.tar.gz serves Apple Silicon and
 * Intel alike — the updater picks the manifest entry matching the *running*
 * process's arch, not a separate build per arch.
 */
import fs from 'node:fs';
import path from 'node:path';

const [, , version, bundleDir, outDir] = process.argv;
if (!version || !bundleDir || !outDir) {
	console.error('usage: node scripts/updater-manifest.mjs <version> <bundleDir> <outDir>');
	process.exit(1);
}

const macosDir = path.join(bundleDir, 'macos');
const tarball = fs.readdirSync(macosDir).find((f) => f.endsWith('.app.tar.gz'));
if (!tarball) {
	console.error(`no *.app.tar.gz found in ${macosDir} — is bundle.createUpdaterArtifacts set?`);
	process.exit(1);
}

const sigPath = path.join(macosDir, `${tarball}.sig`);
if (!fs.existsSync(sigPath)) {
	console.error(`no signature at ${sigPath} — was TAURI_SIGNING_PRIVATE_KEY set for this build?`);
	process.exit(1);
}
const signature = fs.readFileSync(sigPath, 'utf8').trim();

const assetName = `MacClean_${version}_universal.app.tar.gz`;
fs.mkdirSync(outDir, { recursive: true });
fs.copyFileSync(path.join(macosDir, tarball), path.join(outDir, assetName));

// A short, human-facing note for the in-app update prompt — pulled from the
// same "### Changes" section next-version.mjs generates for the GitHub
// release itself, so there's one source of truth for "what changed".
let notes = `MacClean v${version}`;
try {
	const body = fs.readFileSync('RELEASE_NOTES.md', 'utf8');
	const match = body.match(/###\s*Changes\s*\n([\s\S]*?)(\n###|\n$|$)/i);
	const bullets = match
		? match[1]
				.split('\n')
				.map((l) => l.trim())
				.filter((l) => l.startsWith('-'))
		: [];
	if (bullets.length) notes = bullets.join('\n');
} catch {
	/* RELEASE_NOTES.md not present — keep the plain fallback above */
}

const url = `https://github.com/bkrajendra/macclean/releases/download/v${version}/${assetName}`;
const manifest = {
	version,
	notes,
	pub_date: new Date().toISOString(),
	platforms: {
		'darwin-aarch64': { signature, url },
		'darwin-x86_64': { signature, url }
	}
};

fs.writeFileSync(path.join(outDir, 'latest.json'), JSON.stringify(manifest, null, '\t') + '\n');
console.log(`wrote ${path.join(outDir, 'latest.json')} and ${assetName}`);
