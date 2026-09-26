#!/usr/bin/env node
/**
 * post-commit hook: stamps the next semantic version into the repo's version
 * files (package.json, tauri.conf.json, both Cargo.toml [package] sections)
 * and folds it into the commit that was just made, via `git commit --amend`
 * — so the bump rides inside your own commit instead of landing later as a
 * separate bot commit on `main` (which is what used to force a `git pull`
 * before every push). See docs/release-process.md.
 *
 * This runs in `post-commit`, not `commit-msg` or `pre-commit`, on purpose:
 * git snapshots the tree for the commit *before* `commit-msg` runs, so
 * staging files there never actually reaches the commit (confirmed by
 * testing — the hook reported success but the bump silently didn't land).
 * `pre-commit` runs even earlier and has no access to the commit message at
 * all. `post-commit` is the first point where the commit truly exists, so
 * amending it is the only point that's both correct and message-aware. This
 * does mean the commit's SHA changes right after `git commit` prints it —
 * expected, same as any other auto-fix-and-amend hook.
 *
 * Uses the exact same classifier as CI's `scripts/next-version.mjs`
 * (`scripts/lib/versioning.mjs`), fed with every commit since the last tag
 * (HEAD, i.e. the commit just made, is included by that range), so the
 * result matches what CI will independently compute once this is pushed and
 * released.
 *
 * Self-terminating, not recursive: the amend below re-fires this hook, but
 * by then the files already match the computed version, so the second pass
 * returns immediately at the "already correct" check.
 *
 * Never blocks anything: any failure here is logged to stderr and swallowed.
 */
import { execSync } from 'node:child_process';
import {
	classifyBump,
	currentVersion,
	lastTag,
	nextVersion,
	stampVersion
} from '../lib/versioning.mjs';

function main() {
	const subject = execSync('git log -1 --pretty=%s', { encoding: 'utf8' }).trim();
	if (/^Merge /.test(subject) || /^chore\(release\):/.test(subject)) return;

	const prev = lastTag();
	const range = prev ? `${prev}..HEAD` : 'HEAD';
	const messages = execSync(`git log ${range} --no-merges --pretty=format:%s%x1f%b%x1e`, {
		encoding: 'utf8'
	})
		.split('\x1e')
		.map((c) => c.trim())
		.filter(Boolean)
		.map((c) => c.replace('\x1f', '\n'));

	const { bump, releasable } = classifyBump(messages);
	if (!releasable) return; // chore/docs/style/etc — leave version files untouched

	const version = nextVersion(prev, bump);
	if (version === currentVersion()) return; // already correct — nothing to do

	stampVersion(version);
	execSync(
		'git add package.json src-tauri/tauri.conf.json src-tauri/Cargo.toml src-tauri/crates/macclean-core/Cargo.toml'
	);
	execSync('git commit --amend --no-edit --no-verify', { stdio: 'ignore' });
	console.log(`[post-commit] stamped version ${version} into the commit`);
}

try {
	main();
} catch (e) {
	console.error(`[post-commit] version-stamp hook failed, continuing without it: ${e.message}`);
}
process.exit(0);
