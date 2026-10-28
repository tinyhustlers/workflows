// Release rule check: versions go v0.01, v0.02 ... v0.10, v0.11, always +0.01.
// Compares the top "## vX.YY" entry of CHANGELOG.md on the PR against the base branch.
// Usage: node check-version.mjs <base-changelog-file|-> <head-changelog-file> [--require]
import { readFileSync, existsSync } from 'node:fs';

/** Top version in a changelog, as hundredths (v0.13 -> 13), or null. */
export function topVersion(text) {
  const m = String(text ?? '').match(/^##\s*v?(\d+)\.(\d{2})\b/m);
  return m ? Number(m[1]) * 100 + Number(m[2]) : null;
}

export const fmt = (n) => `v${Math.floor(n / 100)}.${String(n % 100).padStart(2, '0')}`;

/** Returns { ok, level: 'pass'|'warn'|'fail', message }. */
export function check(baseText, headText, requireRelease = false) {
  const head = topVersion(headText);
  const base = topVersion(baseText);
  if (head === null) {
    return requireRelease
      ? { ok: false, level: 'fail', message: 'CHANGELOG.md has no "## vX.YY" entry.' }
      : { ok: true, level: 'warn', message: 'No CHANGELOG.md version found; skipping the version check.' };
  }
  if (base === null) {
    return { ok: true, level: 'pass', message: `First release ${fmt(head)}.` };
  }
  if (head === base) {
    return requireRelease
      ? { ok: false, level: 'fail', message: `Version not bumped: still ${fmt(head)}. Each release is exactly +0.01.` }
      : { ok: true, level: 'warn', message: `No version bump (${fmt(head)}). Fine for a non-release PR.` };
  }
  if (head === base + 1) return { ok: true, level: 'pass', message: `Version ${fmt(base)} -> ${fmt(head)}.` };
  return { ok: false, level: 'fail', message: `Version must go ${fmt(base)} -> ${fmt(base + 1)}, found ${fmt(head)}.` };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [basePath, headPath, flag] = process.argv.slice(2);
  const read = (p) => (p && p !== '-' && existsSync(p) ? readFileSync(p, 'utf8') : '');
  const r = check(read(basePath), read(headPath), flag === '--require');
  const tag = r.level === 'fail' ? '::error title=Version check::' : r.level === 'warn' ? '::warning title=Version check::' : '';
  console.log(`${tag}${r.message}`);
  process.exit(r.ok ? 0 : 1);
}
