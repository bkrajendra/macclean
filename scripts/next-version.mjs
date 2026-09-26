#!/usr/bin/env node
/**
 * Determine the next semantic version from git tags + Conventional Commits.
 * CI's independent check: it never trusts the version already stamped in the
 * files (that's `scripts/git-hooks/post-commit.mjs`'s job locally) — it always
 * recomputes from tags + commit log, using the same `scripts/lib/versioning.mjs`
 * classifier, so a commit made without the local hook still gets a correct
 * version at build time.
 *
 *   - No `v*.*.*` tag yet            → 1.0.0  (the first native release)
 *   - `feat!:` / `BREAKING CHANGE:`  → major
 *   - `feat:`                        → minor
 *   - anything else                  → patch
 *
 * Writes `version`, `tag`, `prev`, `first`, `notes_file` to $GITHUB_OUTPUT when
 * present, and prints a JSON summary to stdout. Never fails the build.
 */
import { execSync } from 'node:child_process';
import fs from 'node:fs';
import { classifyBump, lastTag, nextVersion } from './lib/versioning.mjs';

const sh = (cmd) => execSync(cmd, { encoding: 'utf8' }).trim();

const prev = lastTag();
const first = prev === null;

// `releasable` = there is at least one feat / fix / perf / breaking change since
// the last tag. A run with only chore/docs/ci/test/style/refactor commits builds
// and tests on CI but does not cut a new version (avoids version churn).
let commits = []; // [{ subject, body }]
let bump = 'patch';
let releasable = first;

if (!first) {
	const raw = sh(`git log ${prev}..HEAD --no-merges --pretty=format:%s%x1f%b%x1e`);
	commits = raw
		.split('\x1e')
		.map((c) => c.trim())
		.filter(Boolean)
		.map((c) => {
			const [subject, body = ''] = c.split('\x1f');
			return { subject, body };
		});
	({ bump, releasable } = classifyBump(commits.map((c) => `${c.subject}\n${c.body}`)));
}

const version = nextVersion(prev, bump);
const tag = `v${version}`;
const date = new Date().toISOString().slice(0, 10);

const changeLines = first
	? ['- First native release: full rewrite from Python to Svelte 5 + Tauri 2 + Rust.']
	: commits
			.map((c) => c.subject)
			.filter((s) => /^(feat|fix|perf|refactor|build|docs)(\([^)]*\))?!?:/.test(s))
			.map((s) => `- ${s}`);

const notes = `## MacClean ${tag}

Released ${date}

### Supported architectures
- Apple Silicon (\`aarch64-apple-darwin\`) and Intel (\`x86_64-apple-darwin\`) — shipped as a universal binary.
- Requires macOS 11 (Big Sur) or later.

### Install
1. Download \`MacClean_${version}_universal.dmg\`.
2. Open it and drag **MacClean** to Applications.
3. First launch: right-click ▸ Open (the build is not yet Apple-notarised — see below).
4. For system-level cache locations, grant **Full Disk Access** in System Settings ▸ Privacy & Security.

### Changes
${changeLines.length ? changeLines.join('\n') : '- Maintenance release.'}

### Permission requirements
MacClean runs as a normal user app (never \`sudo\`). It asks for Full Disk Access only to reach TCC-protected cache directories; denied paths are reported, never silently skipped.

### Known limitations
- Not yet code-signed / notarised (Gatekeeper prompt on first launch). The release pipeline activates signing automatically once Apple credentials are added as repository secrets.
- The auto-updater is scaffolded but disabled until an updater signing key is configured.
`;

const notesFile = 'RELEASE_NOTES.md';
fs.writeFileSync(notesFile, notes);

if (process.env.GITHUB_OUTPUT) {
	fs.appendFileSync(
		process.env.GITHUB_OUTPUT,
		`version=${version}\ntag=${tag}\nprev=${prev ?? ''}\nfirst=${first}\nreleasable=${releasable}\nnotes_file=${notesFile}\n`
	);
}

console.log(JSON.stringify({ version, tag, prev, first, releasable, notesFile }, null, 2));
