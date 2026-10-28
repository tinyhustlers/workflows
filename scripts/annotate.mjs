// Turn OSV-Scanner or Semgrep JSON into GitHub annotations and a summary table,
// so findings show on the PR (and in the GitHub phone app), not only in raw logs.
// Usage: node annotate.mjs osv|semgrep <report.json>
// Exit code: 1 when there are findings, else 0.
import { readFileSync, appendFileSync, existsSync } from 'node:fs';

const esc = (s) => String(s ?? '').replace(/%/g, '%25').replace(/\r/g, '').replace(/\n/g, ' ').slice(0, 300);

/** OSV report -> [{file, title, detail}] one row per vulnerable package. */
export function fromOsv(report) {
  const rows = [];
  for (const res of report?.results ?? []) {
    for (const pkg of res.packages ?? []) {
      const ids = (pkg.vulnerabilities ?? []).map((v) => v.id);
      if (!ids.length) continue;
      const sev = Math.max(0, ...(pkg.groups ?? []).map((g) => Number(g.max_severity) || 0));
      const first = (pkg.vulnerabilities ?? [])[0]?.summary ?? '';
      rows.push({
        file: res.source?.path?.replace(/^\/?(home\/runner\/work\/[^/]+\/[^/]+\/)?/, '') ?? '',
        title: `${pkg.package?.name}@${pkg.package?.version}`,
        detail: `${ids.length} known vulnerabilit${ids.length > 1 ? 'ies' : 'y'}${sev ? `, max CVSS ${sev}` : ''}: ${ids.slice(0, 3).join(', ')}${first ? ` (${first})` : ''}`,
      });
    }
  }
  return rows;
}

/** Semgrep report -> [{file, line, title, detail}] */
export function fromSemgrep(report) {
  return (report?.results ?? []).map((r) => ({
    file: r.path,
    line: r.start?.line,
    title: r.check_id?.split('.').pop() ?? 'semgrep',
    detail: r.extra?.message ?? '',
  }));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [kind, path] = process.argv.slice(2);
  const report = existsSync(path) ? JSON.parse(readFileSync(path, 'utf8') || '{}') : {};
  const rows = kind === 'osv' ? fromOsv(report) : fromSemgrep(report);
  for (const r of rows) {
    const loc = [r.file && `file=${r.file}`, r.line && `line=${r.line}`].filter(Boolean).join(',');
    console.log(`::error ${loc ? `${loc},` : ''}title=${esc(r.title)}::${esc(r.detail)}`);
  }
  if (process.env.GITHUB_STEP_SUMMARY && rows.length) {
    const name = kind === 'osv' ? 'Vulnerable packages' : 'Risky code (high severity)';
    const lines = [`#### ${name}: ${rows.length}`, '| Where | What | Detail |', '| --- | --- | --- |',
      ...rows.slice(0, 50).map((r) => `| ${r.file}${r.line ? `:${r.line}` : ''} | ${r.title} | ${esc(r.detail).replace(/\|/g, '/')} |`)];
    appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${lines.join('\n')}\n`);
  }
  console.log(`${rows.length} finding(s).`);
  process.exit(rows.length ? 1 : 0);
}
