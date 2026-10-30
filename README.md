# Spunky Tensor repository baseline

This baseline provides security automation for **public and private** repositories.
It requires no paid GitHub security add-ons, Dependency Graph, dependency-review service, hosted CodeQL, Advanced Security, or SARIF upload.
Actions minutes and storage can incur charges.
See [AGENTS.md](AGENTS.md) for policy and documentation rules.

## Run locally or in any CI

Install Bash, Python 3, jq, and GNU coreutils on Linux.
Install **Trivy 0.76.1** from its official release.
Use a reviewed checkout of this repository.
Run these commands:

```sh
bash scripts/scan.sh source /path/to/project /path/to/new-report-directory
bash scripts/scan.sh image registry/project@sha256:PLATFORM_MANIFEST_DIGEST /path/to/new-image-reports
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
A successful scan becomes stale after 36 hours.
Local mode makes no API calls.
GitHub mode uses `gh` with `--visibility public|private|all` and requires repository access.
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

### Amp orbs

`.agents/setup` installs Python 3.12, `requirements.txt` dependencies, actionlint 1.7.12, and Trivy 0.76.1.
It verifies tool checksums and reuses installed dependencies.
It stores the environment at `~/.cache/amp/spunkytensor-baseline`, outside source scans.
New login shells in this checkout use that environment automatically.
Run `.agents/setup` after requirements change.

`.agents/resume` checks tool availability without network access or installation.
Setup requires no services, tokens, or authentication.
Setup requires internet access and Amp's x64 Debian orb template with preinstalled `uv`.

### Local checks

```sh
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python -m bandit -r scripts -lll
actionlint .github/workflows/*.yml
```

Keep actions and tools pinned.
Tests cover scan success and failure.
Run a live Trivy scan after changes to scanner integration.
Original material uses Apache-2.0.
See [LICENSE](LICENSE) and [third-party notices](THIRD_PARTY_NOTICES.txt).
