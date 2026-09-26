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
 * Also resyncs src-tauri/Cargo.lock, which is not itself one of the files
 * this hook writes but carries its own copy of macclean's/macclean-core's
 * version (Cargo keeps every workspace member's Cargo.lock entry in sync
 * with its manifest on any invocation, including background ones like an
 * IDE's rust-analyzer). Left alone, that resync happens *after* this commit,
 * on its own, landing as a separate uncommitted change every time — the
 * `cargo check` below forces it to happen here instead, so it amends into
 * the same commit as everything else and nothing is ever left dangling.
 *
 * Never blocks anything: any failure here is logged to stderr and swallowed.
 */
import { execSync } from 'node:child_process';
import {
	CARGO_LOCK_FILE,
	classifyBump,
	currentVersion,
	lastTag,
	nextVersion,
	stampVersion,
	VERSION_FILES
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

	try {
		// Side effect only: forces Cargo to resync Cargo.lock's macclean /
		// macclean-core entries against the manifests just written above,
		// right now, in this commit — instead of whatever next touches the
		// workspace (a build, a test run, rust-analyzer) doing it later as a
		// stray uncommitted diff. Best effort: a failure here (e.g. a
		// genuinely broken build) must not stop the manifest bump above from
		// still landing.
		execSync('cargo check --offline --manifest-path src-tauri/Cargo.toml', { stdio: 'ignore' });
	} catch (e) {
		console.error(`[post-commit] Cargo.lock resync skipped (non-fatal): ${e.message}`);
	}

	execSync(`git add ${VERSION_FILES.join(' ')} ${CARGO_LOCK_FILE}`);
	execSync('git commit --amend --no-edit --no-verify', { stdio: 'ignore' });
	console.log(`[post-commit] stamped version ${version} into the commit`);
}

try {
	main();
} catch (e) {
	console.error(`[post-commit] version-stamp hook failed, continuing without it: ${e.message}`);
}
process.exit(0);
