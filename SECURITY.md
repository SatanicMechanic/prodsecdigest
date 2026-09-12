# Security Policy

## Reporting a Vulnerability

**Do not open a public issue.**

Use GitHub's private vulnerability reporting:

1. Go to the **Security** tab → **Report a vulnerability** (or `https://github.com/SatanicMechanic/prodsecdigest/security/advisories/new`).
2. Describe the issue, impact, and reproduction steps.

Private reports are visible only to maintainers until triaged. You will receive an acknowledgment within 72 hours.

For forks: report against the upstream template (`SatanicMechanic/prodsecdigest`) if the issue is in template code. Report against the fork directly if the issue is fork-specific (secrets, provider keys, deployment config) — do not paste secrets or live credentials in the report.

## Supported Versions

Only `main` is supported. Fixes are committed to `main` and propagate to private forks via the `Sync from upstream` workflow (weekly merge).

## Scope

This repository is a **public template** — it is inert on `SatanicMechanic/prodsecdigest` (scheduled workflows are gated `if: github.repository != 'SatanicMechanic/prodsecdigest'`). Live secrets (`GH_MODELS_TOKEN`, `XAI_API_KEY`, `BRAVE_API_KEY`, etc.) exist only in private forks. Do not include live credentials in reports or reproductions.

## What to Expect

- Acknowledgment within 72 hours.
- Fix or mitigation on `main` once validated. No bug bounty program.
- Coordinated disclosure: please allow time to merge and for forks to sync before public disclosure.
