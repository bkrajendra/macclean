/**
 * Shared semantic-versioning logic used by `scripts/next-version.mjs` (CI's
 * independent computation), `scripts/set-version.mjs` (file stamping) and
 * `scripts/git-hooks/post-commit.mjs` (the local pre-push stamping hook). Keeping
 * one implementation means the hook and CI can never classify a commit
 * differently.
 */
import { execSync } from 'node:child_process';
import fs from 'node:fs';

/** The most recent `vX.Y.Z` tag, or `null` if none exists yet. */
export function lastTag() {
	try {
		const out = execSync('git tag --list "v*.*.*" --sort=-v:refname', {
			encoding: 'utf8'
		}).trim();
		return out.split('\n').filter(Boolean)[0] ?? null;
	} catch {
		return null;
	}
}

/**
 * Classify a set of full commit messages (subject + body, one string each)
 * against Conventional Commits:
 *   - `type!:` in the subject, or `BREAKING CHANGE` anywhere in the message → major
 *   - `feat:`                                                               → minor
 *   - `fix:` / `perf:`                                                      → patch, and marks the set releasable
 *   - anything else                                                        → no bump on its own
 *
 * `releasable` is false only when every message is chore/docs/style/etc —
 * that's the signal CI uses to skip cutting a release for a maintenance-only
 * push.
 */
export function classifyBump(fullMessages) {
	let bump = 'patch';
	let releasable = false;
	for (const msg of fullMessages) {
		const subject = msg.split('\n')[0] ?? '';
		if (/^[a-z]+(\([^)]*\))?!:/.test(subject) || /BREAKING CHANGE/.test(msg)) {
			bump = 'major';
			releasable = true;
			break;
		}
		if (/^feat(\([^)]*\))?:/.test(subject)) {
			bump = 'minor';
			releasable = true;
		}
		if (/^(fix|perf)(\([^)]*\))?:/.test(subject)) releasable = true;
	}
	return { bump, releasable };
}

/** Apply `bump` to `prevTag` (e.g. `"v1.2.3"`); `null` prevTag → the first release, `1.0.0`. */
export function nextVersion(prevTag, bump) {
	if (!prevTag) return '1.0.0';
	const [maj, min, pat] = prevTag.slice(1).split('.').map(Number);
	if (bump === 'major') return `${maj + 1}.0.0`;
	if (bump === 'minor') return `${maj}.${min + 1}.0`;
	return `${maj}.${min}.${pat + 1}`;
}

/** Write `version` into package.json, tauri.conf.json and both Cargo.toml `[package]` sections. */
export function stampVersion(version) {
	if (!/^\d+\.\d+\.\d+$/.test(version ?? '')) {
		throw new Error(`invalid version: ${version}`);
	}

	function bumpJsonVersion(path) {
		const raw = fs.readFileSync(path, 'utf8');
		const bumped = raw.replace(/("version"\s*:\s*)"[^"]*"/, `$1"${version}"`);
		if (bumped === raw) throw new Error(`no "version" key found in ${path}`);
		fs.writeFileSync(path, bumped);
	}

	bumpJsonVersion('package.json');
	bumpJsonVersion('src-tauri/tauri.conf.json');

	for (const path of ['src-tauri/Cargo.toml', 'src-tauri/crates/macclean-core/Cargo.toml']) {
		const src = fs.readFileSync(path, 'utf8');
		fs.writeFileSync(path, src.replace(/^version = ".*"$/m, `version = "${version}"`));
	}
}

/** The files `stampVersion` writes directly. */
export const VERSION_FILES = [
	'package.json',
	'src-tauri/tauri.conf.json',
	'src-tauri/Cargo.toml',
	'src-tauri/crates/macclean-core/Cargo.toml'
];

/**
 * `src-tauri/Cargo.lock` is not in `VERSION_FILES` — `stampVersion` never
 * writes it directly — but it still carries its own copy of `macclean`'s and
 * `macclean-core`'s version (Cargo keeps every `[[package]]` entry, including
 * local workspace members, in sync with their manifest on any invocation).
 * `post-commit.mjs` stages this too, after running `cargo check` to force
 * that resync, so the lockfile never lags the commit that bumped the
 * manifests — see that file for why.
 */
export const CARGO_LOCK_FILE = 'src-tauri/Cargo.lock';

/** The current version, read from `package.json` (the same source of truth `set-version.mjs` writes first). */
export function currentVersion() {
	return JSON.parse(fs.readFileSync('package.json', 'utf8')).version;
}
