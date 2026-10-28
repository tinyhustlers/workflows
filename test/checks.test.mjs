import { test } from 'node:test';
import assert from 'node:assert/strict';
import { check, topVersion } from '../scripts/check-version.mjs';
import { analyse } from '../scripts/check-supabase-rls.mjs';

const cl = (...v) => v.map((x) => `## ${x} (2026-10-28)\n- change`).join('\n\n');

test('reads the top version', () => {
  assert.equal(topVersion(cl('v0.13', 'v0.12')), 13);
  assert.equal(topVersion('# Changelog\n\n## v1.02'), 102);
  assert.equal(topVersion('nothing'), null);
});

test('+0.01 passes, skips and wrong bumps fail', () => {
  assert.equal(check(cl('v0.09'), cl('v0.10', 'v0.09')).level, 'pass');
  assert.equal(check(cl('v0.09'), cl('v0.11')).level, 'fail');
  assert.equal(check(cl('v0.09'), cl('v0.08')).level, 'fail');
  assert.equal(check(cl('v0.09'), cl('v0.09')).level, 'warn');
  assert.equal(check(cl('v0.09'), cl('v0.09'), true).level, 'fail');
  assert.equal(check('', cl('v0.01')).level, 'pass');
  assert.equal(check('', '', true).level, 'fail');
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
