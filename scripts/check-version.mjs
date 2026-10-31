// Release rule check: Semantic Versioning (MAJOR.MINOR.PATCH), one step at a time.
// Allowed next versions from X.Y.Z: X.Y.(Z+1) (fixes), X.(Y+1).0 (features), (X+1).0.0 (launch / breaking).
// Compares the top "## vX.Y.Z" entry of CHANGELOG.md on the PR against the base branch.
// Old "## v0.NN" headings (before 2026-10-30) read as 0.NN.0.
// Usage: node check-version.mjs <base-changelog-file|-> <head-changelog-file> [--require]
import { readFileSync, existsSync } from 'node:fs';

/** Top version in a changelog as [major, minor, patch], or null. */
export function topVersion(text) {
  const m = String(text ?? '').match(/^##\s*v?(\d+)\.(\d+)(?:\.(\d+))?\b/m);
  return m ? [Number(m[1]), Number(m[2]), Number(m[3] ?? 0)] : null;
}

export const fmt = (v) => `v${v.join('.')}`;
const same = (a, b) => a.every((n, i) => n === b[i]);

/** The three versions a release may move to from `v`. */
export function nextVersions([a, b, c]) {
  return { patch: [a, b, c + 1], minor: [a, b + 1, 0], major: [a + 1, 0, 0] };
}

/** Returns { ok, level: 'pass'|'warn'|'fail', message }. */
export function check(baseText, headText, requireRelease = false) {
  const head = topVersion(headText);
  const base = topVersion(baseText);
  if (head === null) {
    return requireRelease
      ? { ok: false, level: 'fail', message: 'CHANGELOG.md has no "## vX.Y.Z" entry.' }
      : { ok: true, level: 'warn', message: 'No CHANGELOG.md version found; skipping the version check.' };
  }
  if (base === null) return { ok: true, level: 'pass', message: `First release ${fmt(head)}.` };
  if (same(head, base)) {
    return requireRelease
      ? { ok: false, level: 'fail', message: `Version not bumped: still ${fmt(head)}.` }
      : { ok: true, level: 'warn', message: `No version bump (${fmt(head)}). Fine for a non-release PR.` };
  }
  const next = nextVersions(base);
  for (const [kind, v] of Object.entries(next)) {
    if (same(head, v)) return { ok: true, level: 'pass', message: `Version ${fmt(base)} -> ${fmt(head)} (${kind}).` };
  }
  return {
    ok: false, level: 'fail',
    message: `Version must go ${fmt(base)} -> ${fmt(next.patch)} (fixes), ${fmt(next.minor)} (features) or ${fmt(next.major)} (launch/breaking); found ${fmt(head)}.`,
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [basePath, headPath, flag] = process.argv.slice(2);
  const read = (p) => (p && p !== '-' && existsSync(p) ? readFileSync(p, 'utf8') : '');
  const r = check(read(basePath), read(headPath), flag === '--require');
  const tag = r.level === 'fail' ? '::error title=Version check::' : r.level === 'warn' ? '::warning title=Version check::' : '';
  console.log(`${tag}${r.message}`);
  process.exit(r.ok ? 0 : 1);
}
