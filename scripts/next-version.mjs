#!/usr/bin/env node
/**
 * Determine the next semantic version from git tags + Conventional Commits.
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

const sh = (cmd) => execSync(cmd, { encoding: 'utf8' }).trim();

function tagList() {
	try {
		return sh('git tag --list "v*.*.*" --sort=-v:refname').split('\n').filter(Boolean);
	} catch {
		return [];
	}
}

const tags = tagList();
const prev = tags[0] ?? null;
const first = prev === null;

let version;
let commits = [];

if (first) {
	version = '1.0.0';
} else {
	const [maj, min, pat] = prev.slice(1).split('.').map(Number);
	const raw = sh(`git log ${prev}..HEAD --no-merges --pretty=format:%s%x1f%b%x1e`);
	commits = raw
		.split('\x1e')
		.map((c) => c.trim())
		.filter(Boolean);

	let bump = 'patch';
	for (const c of commits) {
		const subject = c.split('\x1f')[0] ?? '';
		if (/^[a-z]+(\([^)]*\))?!:/.test(subject) || /BREAKING CHANGE/.test(c)) {
			bump = 'major';
			break;
		}
		if (/^feat(\([^)]*\))?:/.test(subject)) bump = 'minor';
	}

	if (bump === 'major') version = `${maj + 1}.0.0`;
	else if (bump === 'minor') version = `${maj}.${min + 1}.0`;
	else version = `${maj}.${min}.${pat + 1}`;
}

const tag = `v${version}`;
const date = new Date().toISOString().slice(0, 10);

const changeLines = first
	? ['- First native release: full rewrite from Python to Svelte 5 + Tauri 2 + Rust.']
	: commits
			.map((c) => c.split('\x1f')[0])
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
		`version=${version}\ntag=${tag}\nprev=${prev ?? ''}\nfirst=${first}\nnotes_file=${notesFile}\n`
	);
}

console.log(JSON.stringify({ version, tag, prev, first, notesFile }, null, 2));
