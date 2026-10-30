# Spunky Tensor repository baseline

This baseline provides security automation for **public and private** repositories.
It requires no paid GitHub security add-ons, Dependency Graph, dependency-review service, hosted CodeQL, Advanced Security, or SARIF upload.
Actions minutes and storage can incur charges.
See [AGENTS.md](AGENTS.md) for policy and documentation rules.

## Run locally or in any CI

Install Bash, Python 3, jq, and GNU coreutils on Linux.
Install **Trivy 0.76.1** from its official release.
Use a reviewed checkout of this repository.
For source scans, run:

```sh
bash scripts/scan.sh source /path/to/project /path/to/new-report-directory
```

For image scans, run:

```sh
bash scripts/scan.sh image registry/project@sha256:PLATFORM_MANIFEST_DIGEST /path/to/new-image-reports
```

To check an existing report, run:

```sh
python3 scripts/check_report.py /path/to/new-report-directory/trivy.json
```

Use new report directories outside the source directory.
Scans produce reports, SBOMs, metadata, and checksums before the vulnerability check.
High/Critical vulnerabilities fail the check, including unfixed findings.
Empty or malformed inventories and tool failures also fail the check.
Provide internet access for fresh vulnerability databases.
Caller configuration, ignore files, and `TRIVY_*` overrides cannot weaken policy.

## GitHub Actions

[Onboarding](docs/onboarding.md) covers workflow callers, immutable pins, image scans, report retention, and adoption checks.
Workflows require explicit callers.
Community-file defaults apply separately from workflow adoption.

This repository runs source scans, tests, and Bandit analysis on pull requests, main-branch pushes, and nightly at 10:07 UTC.
Bandit lacks CodeQL dataflow coverage.
Trivy provides no dependency-review pull-request comparison interface.
Keep project-specific security checks.

## Freshness and privacy

```sh
python3 scripts/check_scan_freshness.py --github-org spunkytensor
python3 scripts/check_scan_freshness.py --input scheduled-runs.json
```

Supply your scheduler's inventory of expected repositories and checks.
See the script's module docstring for the JSON schema.
The check fails for missing, failed, disabled, or stale scans.
A successful scheduled run becomes stale more than 36 hours after its start.
Local mode makes no API calls.
GitHub mode uses `gh` with `--visibility public|private|all` and requires repository access.
GitHub mode checks scheduled workflow runs on each repository's default branch.
A token can omit repositories from its visible inventory.

Keep `coverage.yml` **public-only**.
Keep private-repository tokens, names, and findings out of this public repository.
Run private monitoring in a private repository or trusted local runner.
A repository's `GITHUB_TOKEN` grants no access to other private repositories.
Check the freshness reporter's own freshness.
Track separate runtime checks.

## Scope and adoption

[The baseline](docs/baseline.md) defines inventory, attribution, release evidence, and triage requirements.
Trivy cannot prove inventory completeness or generate legally sufficient license notices.

## Development

See the [development guide](docs/development.md) for orb setup and local checks.
