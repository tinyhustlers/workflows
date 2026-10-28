// Supabase access-rule check over SQL migrations.
// Fails when a table in an API-exposed schema has no "enable row level security",
// or when a policy lets everyone through (using (true) / with check (true)) for anon.
// Usage: node check-supabase-rls.mjs [migrations-dir ...]
import { readdirSync, readFileSync, statSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const EXPOSED = new Set(['public']);

const norm = (name) => name.replace(/"/g, '').toLowerCase();
const split = (q) => {
  const parts = norm(q).split('.');
  return parts.length === 2 ? { schema: parts[0], table: parts[1] } : { schema: 'public', table: parts[0] };
};

/** Analyse SQL text; returns { tables, rls, problems } */
export function analyse(sql) {
  const text = String(sql).replace(/--.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '');
  const tables = new Map();
  const rls = new Set();
  const problems = [];
  const ident = '((?:"[^"]+"|\\w+)(?:\\.(?:"[^"]+"|\\w+))?)';

  for (const m of text.matchAll(new RegExp(`create\\s+table\\s+(?:if\\s+not\\s+exists\\s+)?${ident}`, 'gi'))) {
    const t = split(m[1]);
    if (EXPOSED.has(t.schema)) tables.set(`${t.schema}.${t.table}`, true);
  }
  for (const m of text.matchAll(new RegExp(`alter\\s+table\\s+(?:only\\s+)?(?:if\\s+exists\\s+)?${ident}\\s+enable\\s+row\\s+level\\s+security`, 'gi'))) {
    const t = split(m[1]);
    rls.add(`${t.schema}.${t.table}`);
  }
  for (const m of text.matchAll(new RegExp(`alter\\s+table\\s+(?:only\\s+)?(?:if\\s+exists\\s+)?${ident}\\s+disable\\s+row\\s+level\\s+security`, 'gi'))) {
    const t = split(m[1]);
    rls.delete(`${t.schema}.${t.table}`);
    problems.push(`${t.schema}.${t.table}: row level security is disabled.`);
  }
  for (const m of text.matchAll(new RegExp(`create\\s+policy\\s+("[^"]+"|\\w+)\\s+on\\s+${ident}([\\s\\S]*?);`, 'gi'))) {
    const t = split(m[2]);
    const rest = m[3].toLowerCase();
    const open = /(using|with\s+check)\s*\(\s*true\s*\)/.test(rest);
    const forAnon = !/\bto\b/.test(rest) || /\bto\s+[^;]*\b(anon|public)\b/.test(rest);
    if (open && forAnon) problems.push(`${t.schema}.${t.table}: policy ${m[1]} lets anyone through (true) without sign-in.`);
  }
  return { tables: [...tables.keys()], rls, problems };
}

function sqlFiles(dir) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? sqlFiles(p) : f.endsWith('.sql') ? [p] : [];
  }).sort();
}

export function run(dirs) {
  const files = dirs.flatMap(sqlFiles);
  const all = analyse(files.map((f) => readFileSync(f, 'utf8')).join('\n;\n'));
  const missing = all.tables.filter((t) => !all.rls.has(t)).map((t) => `${t}: no "enable row level security".`);
  return { files: files.length, tables: all.tables.length, problems: [...missing, ...all.problems] };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const dirs = process.argv.slice(2).length ? process.argv.slice(2) : ['supabase/migrations'];
  const r = run(dirs);
  if (!r.files) { console.log('No Supabase migrations found; skipping.'); process.exit(0); }
  for (const p of r.problems) console.log(`::error title=Supabase access rules::${p}`);
  console.log(`Checked ${r.tables} table(s) in ${r.files} migration file(s): ${r.problems.length} problem(s).`);
  process.exit(r.problems.length ? 1 : 0);
}
