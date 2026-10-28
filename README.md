# workflows

Shared automation for every Tiny Hustlers app. This repo is public on purpose: it holds only reusable checks,
never secrets, customer data or app code.

## Security check (`.github/workflows/security.yml`)

Runs on every pull request in every app and blocks the merge when it finds:

| # | Check | Tool | Blocks on |
| --- | --- | --- | --- |
| 1 | Leaked keys and passwords | gitleaks 8.24.3 | Any finding |
| 2 | Packages with known vulnerabilities | OSV-Scanner 2.2.2 | Any known vulnerability |
| 3 | Risky code patterns | Semgrep CE (`p/default`) | High-severity findings only |
| 4 | Version rule | `scripts/check-version.mjs` | Version not exactly +0.01 (release PRs into `dev`) |
| 5 | Supabase access rules | `scripts/check-supabase-rls.mjs` | A table without row-level security, or a policy open to anyone |

Scanner binaries are pinned and their SHA-256 checksums verified before running. The job only reads the repo.

### Add it to an app

Copy `templates/security-caller.yml` to `.github/workflows/security.yml` in the app repo. Options:

| Input | Default | Meaning |
| --- | --- | --- |
| `require-release` | `false` | Fail without a +0.01 CHANGELOG bump (the template turns it on for PR titles like "Speakco v0.14: ...") |
| `supabase-migrations` | `supabase/migrations` | Where the SQL migrations live (skipped if missing) |
| `semgrep` | `true` | Run the code scan |

### Private app repos

Private repos can call this workflow because this repo is public. Results show in the PR's Checks tab and in
the run summary table.

## Develop

`node --test` runs the script tests. The `Self-test` workflow also lints the workflow files and runs the
security check on this repo.
