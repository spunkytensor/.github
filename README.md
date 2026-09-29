# Spunky Tensor repository baseline

Shared security automation for **public and private** repositories. GitHub Actions
is supported, but no paid private-repository security add-on is required: no
Dependency Graph/dependency-review prerequisite, hosted CodeQL, Advanced Security,
or SARIF upload. Ordinary Actions minutes and storage can still incur charges.
This policy is recorded in [AGENTS.md](AGENTS.md).

## Run locally or in any CI

On Linux, install Bash, Python 3, jq, GNU coreutils, and **Trivy 0.74.0** from its
official release. Use a reviewed checkout of this repository, then run:

```sh
bash scripts/scan.sh source /path/to/project /path/to/new-report-directory
bash scripts/scan.sh image registry/project@sha256:PLATFORM_MANIFEST_DIGEST /path/to/new-image-reports
python3 scripts/check_report.py /path/to/new-report-directory/trivy.json
```

Report directories must be new and outside scanned source. Scans produce full
Trivy JSON, SPDX and CycloneDX SBOMs, tool/subject metadata and checksums before
gating High/Critical vulnerabilities, including unfixed findings. Empty or malformed
inventories and tool failures fail closed. A fresh database cache is used each run;
internet access to vulnerability databases is required. Caller Trivy configuration,
ignore files and `TRIVY_*` overrides cannot weaken policy. Private registry access
uses the runner's Docker credential store; never pass credentials in image names.

## GitHub Actions

[Onboarding](docs/onboarding.md) provides the same reusable caller for either
visibility. Set the required `baseline-sha` input to the same full reviewed SHA as
the reusable workflow pin. Scripts are checked out at that immutable revision,
not the caller's SHA or mutable `main`. Update both pins together.
The workflow keeps reports in the **calling repository**, including on gate failure.
Private image authentication needs a project-local job running the standalone
script after registry login; the reusable wrapper does not accept registry secrets.

This repository runs source scans, tests, and standalone Bandit Python analysis
nightly at 10:07 UTC and on PRs/pushes. Bandit is not equivalent to CodeQL dataflow
analysis. Full-inventory Trivy scanning replaces the dependency-review service gate,
not its PR-diff UI. Keep additional project-specific security coverage.

## Freshness and privacy

```sh
python3 scripts/check_scan_freshness.py --github-org spunkytensor
python3 scripts/check_scan_freshness.py --input scheduled-runs.json
```

The local JSON schema is documented in the script's module docstring. Supply an
explicit inventory of expected repositories and checks from your scheduler; missing,
failed, disabled, or over-36-hour-old successful scans fail. Local mode makes no API
calls. GitHub mode uses `gh` and supports `--visibility public|private|all` with
appropriate repository access. A token's visible repositories are not proof of a
complete organization inventory.

The public `coverage.yml` remains **public-only**. Never add a private-repository
token to it or publish private names/findings here. Run private monitoring in a
private repository or trusted local runner. A repository's `GITHUB_TOKEN` does not
grant access to other private repositories. Scheduled checks are best effort; watch
the reporter's own freshness. Existing separate runtime checks remain tracked.

## Scope and adoption

[The baseline](docs/baseline.md) covers inventory completeness, attribution, release
evidence and triage. Trivy does not generate legally sufficient license notices or
prove complete inventory. Keep project licenses, third-party notices, advertising
clauses and legal review project-local. No shared SECURITY.md is published until
a confidential reporting route is confirmed.

Community-file defaults and workflow adoption are separate mechanisms. Workflows
always require explicit callers. Existing callers stay on their reviewed SHA until
updated; merging this change does not remove their local dependency-review or
CodeQL jobs. Required-check rules must be updated if check names change.

## Development

```sh
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python -m bandit -r scripts -lll
actionlint .github/workflows/*.yml
```

Keep actions and tools pinned. Tests cover failures as well as passing scans; run a
real Trivy scan when changing integration. Original material is Apache-2.0; see
[LICENSE](LICENSE) and [third-party notices](THIRD_PARTY_NOTICES.txt).
