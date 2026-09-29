# Adopting the shared baseline

Start with a pilot repository. Do not remove existing scans or notices until the
new workflow's coverage has been compared and verified.

## Source scanning

Add this caller as `.github/workflows/security.yml` in the participating project.
Replace `REVIEWED_FULL_COMMIT_SHA` with the published baseline's 40-character
commit SHA and change `main` if the default branch differs.

```yaml
name: Spunky Tensor security
on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: '37 9 * * *'
  workflow_dispatch:

permissions:
  contents: read

jobs:
  source:
    uses: spunkytensor/.github/.github/workflows/trivy.yml@REVIEWED_FULL_COMMIT_SHA
```

The example runs nightly at 09:37 UTC (01:37 PST / 02:37 PDT), off the hour.
Stagger other repositories' minutes. GitHub scheduling is best effort.
The workflow checks out the caller's event commit, including GitHub's merge commit
for pull requests. It parses dependencies without installing or building the
project. Submodules, LFS objects, generated dependencies, and downloaded assets are
not fetched; those need explicit project-specific coverage.

An empty detected package inventory fails. Content-only projects should document
why this dependency scan does not apply, rather than manufacturing a green scan.

## Released container images

Add another call in the project's scheduled/release workflow:

```yaml
  runtime:
    uses: spunkytensor/.github/.github/workflows/trivy.yml@REVIEWED_FULL_COMMIT_SHA
    with:
      image-ref: ghcr.io/spunkytensor/PROJECT@sha256:RELEASE_MANIFEST_DIGEST
      artifact-name: security-runtime-amd64
```

Replace both placeholders with the actual image name and 64-character digest.
Only publicly readable images are supported by this initial workflow. For each
supported architecture, use its platform-specific manifest digest, not a mutable
tag or a multi-platform index. Give each call a unique artifact name.
There is no shared Docker daemon between jobs: a locally built image in a previous
job is not available here. Build-and-scan integration is project-specific and must
not publish untrusted pull-request images just to use this workflow.

## Evidence and permissions

Each call uploads `sbom.spdx.json`, `sbom.cdx.json`, `trivy.json`,
`trivy-version.json`, `subject.json`, and `SHA256SUMS` when generated. Reports stay
available for 30 days (subject to GitHub retention policy), even after a CVE gate
failure. Setup or download failures can leave only partial evidence; the job still
fails. Full JSON includes all vulnerability severities. No secrets are needed and
the workflow neither publishes releases nor uploads SARIF to GitHub code scanning.

The scan runs outside the checked-out source so caller `trivy.yaml` and ignore
files cannot silently change central policy. Repository-specific suppression and
VEX support are deliberately not enabled in this first version.

## Before claiming adoption

- Confirm a private vulnerability reporting route and the project's security
  policy. Enable private reporting in GitHub settings; a Markdown file cannot do
  this. Publish a shared SECURITY.md only after its route has been confirmed.
- Enable the GitHub features in [the baseline](baseline.md), then verify required
  check names from real workflow runs before applying branch rules.
- Keep local licenses/notices and project-specific legal review. Existing local
  community files override the organization defaults; remove them only after
  reviewing the information that would be lost.
- Compare source and runtime coverage with the previous scanner. Verify one
  known-vulnerable case fails and scanner failures cannot pass.
- Integrate full inventory reconciliation, attribution generation, and durable
  release assets/attestations. The reusable scan alone does not complete these.
- Record the owner, supported releases, baseline SHA, coverage gaps, and last
  successful nightly scan. Connect central stale-scan alerting before claiming
  continuously monitored coverage.

Publishing this repository activates supported community defaults for repositories
without local overrides, including private repositories under this owner. It does
not enable scanning, change settings, or grant write access to other repositories.
