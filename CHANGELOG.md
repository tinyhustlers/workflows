# Changelog

## v0.3.0 (2026-10-31)
- Version rule is now Semantic Versioning: a release moves one step, patch (fixes), minor (features) or major
  (launch / breaking). Old `## v0.NN` headings still read as `0.NN.0`, so existing changelogs keep working.
- Template: release PRs are titled `<App> vX.Y.Z: ...`.

## v0.2.0 (2026-10-28)
- Findings from OSV-Scanner and Semgrep now show as annotations on the PR and in a summary table.
- Template: the +0.01 version rule applies to release PRs (title "<App> v0.NN: ...").

## v0.1.0 (2026-10-28)
- Shared security check: leaked keys, vulnerable packages, risky code, +0.01 version rule, Supabase access rules.
- Caller template for app repos; self-test workflow.
