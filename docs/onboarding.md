# Adopt the shared baseline

Start with a pilot repository.
Verify equivalent coverage before you remove existing scans or notices.
One workflow caller supports public and private source repositories without paid GitHub security add-ons.
Actions minutes and storage follow your billing plan.
See the [README](../README.md) for standalone commands and private monitoring.

## Source scans

Add this caller as `.github/workflows/public-repo-security.yml` in the project:

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
    with:
      baseline-sha: REVIEWED_FULL_COMMIT_SHA
```

Replace both `REVIEWED_FULL_COMMIT_SHA` values with the same published, reviewed 40-character baseline commit SHA.
Replace `main` if the project uses another default branch.
The schedule runs nightly at 09:37 UTC.
Stagger schedule minutes across repositories.
GitHub provides best-effort schedule execution.

The workflow scans the caller's event commit, including GitHub's pull-request merge commit.
It parses dependencies without a project build or dependency installation.
It omits submodules, LFS objects, generated dependencies, and downloaded assets.
Add project-specific checks for these components.
Empty package inventories fail the check.
For content-only projects, document why the dependency scan does not apply.

## Released container images

Add this job to the project's scheduled or release workflow:

```yaml
  runtime:
    uses: spunkytensor/.github/.github/workflows/trivy.yml@REVIEWED_FULL_COMMIT_SHA
    with:
      baseline-sha: REVIEWED_FULL_COMMIT_SHA
      image-ref: ghcr.io/spunkytensor/PROJECT@sha256:RELEASE_MANIFEST_DIGEST
      artifact-name: security-runtime-amd64
```

Set both baseline pins as specified for source scans.
Replace `PROJECT` with the image name.
Replace `RELEASE_MANIFEST_DIGEST` with its 64-character platform manifest digest.
Use one call per supported architecture.
Give each call a unique artifact name.
The reusable workflow supports publicly readable images only.
Use platform manifest digests instead of mutable tags or multi-platform index digests.
Jobs share no Docker daemon.
Use project-local integration for images that require a build or authentication.
For private images, run the standalone script after registry login.
Private registry access uses the runner's Docker credential store.
Keep credentials out of image names.
The reusable workflow accepts no registry secrets.
Keep untrusted pull-request images out of public registries.

## Evidence and permissions

Each call uploads these files when the scan generates them:

- `sbom.spdx.json` and `sbom.cdx.json`
- `trivy.json` and `trivy-version.json`
- `subject.json` and `SHA256SUMS`

The caller repository retains reports for 30 days, subject to GitHub retention policy, including after vulnerability check failures.
Setup or download failures can leave partial evidence and fail the job.
Trivy JSON includes all vulnerability severities.
The workflow requires no secrets and publishes neither releases nor SARIF.
The scan runs outside the source directory.
Caller configuration and ignore files cannot change the shared policy.
The shared workflow supports neither repository-specific suppressions nor VEX inputs.

## Adoption checklist

- Confirm a confidential vulnerability reporting route.
- Document the project's security policy.
- Confirm the private route before you publish a shared SECURITY.md.
- Verify check names from workflow runs before you set branch rules.
- Update branch rules when check names change.
- Review replacement coverage before you remove local security jobs.
- Keep project-local licenses, notices, and legal review.
- Review local community files before removal.
  Local files override shared defaults.
- Compare source and runtime coverage with existing scanners.
- Verify that a known vulnerability fails the check.
- Verify that scanner failures fail the check.
- Integrate inventory reconciliation and attribution generation.
- Publish durable release evidence.
- Record the owner, supported releases, baseline commit SHA, coverage gaps, and last successful nightly scan.
- Subscribe to failed Actions runs.
- Verify the freshness reporter's activity.
  It detects this caller path across active public repositories and flags missing or stale scheduled successes.

Community-file defaults apply to repositories without local overrides, including private repositories under this owner.
They enable no scans, change no repository settings, and grant no cross-repository write access.
Workflow adoption requires an explicit caller.
Baseline pin updates preserve local security jobs.
