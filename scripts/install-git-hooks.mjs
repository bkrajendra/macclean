#!/usr/bin/env node
/**
 * Installs a thin shim into .git/hooks/ for each script in scripts/git-hooks/
 * (see that directory, and docs/release-process.md) that execs the real
 * `*.mjs` logic in place. The shim never moves — only its target path is
 * baked in — so the hook logic's own relative imports (e.g.
 * `../lib/versioning.mjs`) keep resolving correctly, unlike copying the
 * script itself into .git/hooks/ (which flattens it out of the source tree
 * and breaks those imports).
 *
 * Wired as npm's `prepare` lifecycle script, so it runs automatically on
 * `npm install` and `npm ci` — no extra setup step, no new dependency (no
 * husky/lefthook).
 *
 * Silently does nothing if there's no `.git` (e.g. installed from a tarball)
 * or in CI (hooks only matter for local commits) — never fails the install.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const gitDir = path.join(repoRoot, '.git');
const hooksSrc = path.join(repoRoot, 'scripts', 'git-hooks');
const hooksDest = path.join(gitDir, 'hooks');

if (process.env.CI) process.exit(0);
if (!fs.existsSync(gitDir) || !fs.statSync(gitDir).isDirectory()) process.exit(0);

const marker = 'scripts/git-hooks/';
const wanted = new Set(
	fs
		.readdirSync(hooksSrc)
		.filter((f) => f.endsWith('.mjs'))
		.map((f) => f.slice(0, -'.mjs'.length))
);

// Remove shims this installer wrote for a hook that's since been renamed or
// removed from scripts/git-hooks/ — otherwise a stale one silently points at
// a .mjs that no longer exists.
for (const name of fs.existsSync(hooksDest) ? fs.readdirSync(hooksDest) : []) {
	if (wanted.has(name)) continue;
	const dest = path.join(hooksDest, name);
	const content =
		fs.existsSync(dest) && fs.statSync(dest).isFile() ? fs.readFileSync(dest, 'utf8') : '';
	if (content.includes(marker)) fs.rmSync(dest);
}

for (const name of wanted) {
	const target = path.join(hooksSrc, `${name}.mjs`);
	const dest = path.join(hooksDest, name);
	const shim = `#!/bin/sh\nexec node ${JSON.stringify(target)} "$@"\n`;
	fs.writeFileSync(dest, shim);
	fs.chmodSync(dest, 0o755);
	console.log(`installed git hook: ${name}`);
}
