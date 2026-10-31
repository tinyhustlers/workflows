import { test } from 'node:test';
import assert from 'node:assert/strict';
import { check, topVersion } from '../scripts/check-version.mjs';
import { analyse } from '../scripts/check-supabase-rls.mjs';

const cl = (...v) => v.map((x) => `## ${x} (2026-10-28)\n- change`).join('\n\n');

test('reads the top version (semver, and old v0.NN headings as 0.NN.0)', () => {
  assert.deepEqual(topVersion(cl('v0.17.0', 'v0.16.1')), [0, 17, 0]);
  assert.deepEqual(topVersion('# Changelog\n\n## v1.2.3'), [1, 2, 3]);
  assert.deepEqual(topVersion(cl('v0.16', 'v0.15')), [0, 16, 0]);
  assert.equal(topVersion('nothing'), null);
});

test('semver: one patch, minor or major step passes; skips and going back fail', () => {
  assert.equal(check(cl('v0.16.0'), cl('v0.16.1', 'v0.16.0')).level, 'pass');
  assert.equal(check(cl('v0.16.1'), cl('v0.17.0')).level, 'pass');
  assert.equal(check(cl('v0.17.4'), cl('v1.0.0')).level, 'pass');
  assert.equal(check(cl('v0.16.0'), cl('v0.16.2')).level, 'fail');
  assert.equal(check(cl('v0.16.1'), cl('v0.17.1')).level, 'fail');
  assert.equal(check(cl('v0.16.1'), cl('v0.18.0')).level, 'fail');
  assert.equal(check(cl('v0.16.1'), cl('v0.16.0')).level, 'fail');
  assert.equal(check(cl('v0.16.0'), cl('v0.16.0')).level, 'warn');
  assert.equal(check(cl('v0.16.0'), cl('v0.16.0'), true).level, 'fail');
  assert.equal(check('', cl('v0.1.0')).level, 'pass');
  assert.equal(check('', '', true).level, 'fail');
});

test('moving from an old v0.NN changelog to semver', () => {
  assert.equal(check(cl('v0.16'), cl('v0.16.0')).level, 'warn');
  assert.equal(check(cl('v0.16'), cl('v0.16.1')).level, 'pass');
  assert.equal(check(cl('v0.16'), cl('v0.17.0')).level, 'pass');
});

test('flags tables without row level security', () => {
  const r = analyse('create table public.notes (id int); create table if not exists "meals" (id int); alter table public.notes enable row level security;');
  assert.deepEqual(r.tables.sort(), ['public.meals', 'public.notes']);
  assert.ok(r.rls.has('public.notes') && !r.rls.has('public.meals'));
});

test('ignores private schemas and comments', () => {
  const r = analyse('-- create table public.x (id int);\ncreate table private.keys (id int);');
  assert.deepEqual(r.tables, []);
});

test('flags open policies for anonymous users only', () => {
  const open = analyse('create policy "all" on public.notes for select using (true);');
  assert.equal(open.problems.length, 1);
  const anon = analyse('create policy p on public.notes for select to anon using (true);');
  assert.equal(anon.problems.length, 1);
  const own = analyse('create policy own on public.notes for select to authenticated using (auth.uid() = user_id);');
  assert.equal(own.problems.length, 0);
  const off = analyse('alter table public.notes disable row level security;');
  assert.equal(off.problems.length, 1);
});

import { fromOsv, fromSemgrep } from '../scripts/annotate.mjs';

test('turns OSV and Semgrep reports into readable rows', () => {
  const osv = { results: [{ source: { path: '/home/runner/work/app/app/package-lock.json' }, packages: [
    { package: { name: 'vite', version: '5.0.0' }, vulnerabilities: [{ id: 'GHSA-1', summary: 'Path traversal' }], groups: [{ max_severity: '7.5' }] },
    { package: { name: 'ok', version: '1.0.0' }, vulnerabilities: [] }] }] };
  const rows = fromOsv(osv);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].file, 'package-lock.json');
  assert.match(rows[0].detail, /GHSA-1.*CVSS 7.5|CVSS 7.5.*GHSA-1/);
  const sg = fromSemgrep({ results: [{ path: 'src/a.ts', start: { line: 3 }, check_id: 'x.y.eval-usage', extra: { message: 'eval is dangerous' } }] });
  assert.deepEqual(sg[0], { file: 'src/a.ts', line: 3, title: 'eval-usage', detail: 'eval is dangerous' });
  assert.equal(fromOsv({}).length, 0);
});
