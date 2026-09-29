# Public and private repository baseline

These are adoption requirements, not a statement of current compliance. Each
project records its maintainer, supported release lines, distributed artifacts,
baseline commit, and any coverage gaps in its own documentation.

## GitHub administration

GitHub Actions is allowed; paid private-repository security services are not a
baseline prerequisite. Use standalone Trivy for dependency vulnerabilities and
language-appropriate free local analyzers (Bandit for this repository's Python).
Hosted CodeQL and dependency review are not required. Free GitHub features such as
Dependabot may complement the baseline but must not be needed to run its scripts.
Use repository-local Dependabot configuration for updates; it is not inherited.
Actions minutes and storage can incur usage charges for private repositories.

Protect default branches with required checks and review. Protect workflow and
policy changes with appropriate code ownership. Require maintainer 2FA and review
access periodically. Use organization settings where the plan supports them;
otherwise configure and verify repository settings individually. Do not assume a
public repository includes every paid organization administration feature.

Actions use least-privilege tokens and full commit pins. Do not execute untrusted
pull-request code in privileged `pull_request_target` jobs. Keep publishing and
attestation credentials out of dependency scans. Prefer short-lived OIDC tokens
over persistent publishing credentials.

## Inventory and SBOM coverage

Inventory both resolved source/build dependencies and actual distributed artifacts.
Distinguish development dependencies from runtime components. For each release and
supported platform, publish `sbom.spdx.json` and `sbom.cdx.json`, alongside the
source commit, artifact digest, tool version, and generation time.

Coverage includes transitive dependencies, OS packages, bundled native libraries,
vendored code, fonts, and other assets. Record model weights and separately
downloaded components where applicable, distinguishing what the project ships
from what the user obtains elsewhere. Record unknown provenance explicitly.

Reconcile inventories against lockfiles, installed-package metadata, and build
outputs. A nonempty SBOM is only a minimum sanity check, not proof of completeness.
Trivy's supported package detection cannot automatically inventory every asset or
prove license compliance. Keep project-specific completeness checks.

## Vulnerabilities and nightly scans

Use Trivy as the shared primary scanner. Retain ecosystem checks where they add
verified coverage. Before removing an existing scanner, compare inventories and
findings against the same source commit and artifact digest, including current
VEX decisions. Do not translate suppressions blindly between scanners.

Run source checks on pull requests and default-branch changes. Run nightly checks
with current vulnerability data for source and supported released artifacts by
immutable digest. Rebuilding current source does not scan an older shipped image.
Multi-platform releases require scans of each platform's image manifest digest.

High and Critical findings block the shared check, including unfixed findings.
Retain lower-severity findings for triage. Tool failures and empty inventories fail
the check rather than being interpreted as clean scans. An end-of-life base image
or an unsupported ecosystem needs explicit review even if no CVEs are reported.

Assign findings an owner and a remediation date based on exploitability and
exposure. Leaked credentials require revocation, not just deletion from Git.
Exceptions require a finding/package/version scope, evidence, owner, reviewer,
expiry, and tracking reference. VEX is a supported applicability conclusion, not a
generic waiver. The initial shared workflow applies no suppressions; an exception
validation mechanism must be reviewed before enabling exceptions.

Track last successful scans and failures across adopted repositories; flag scans
older than 36 hours. GitHub schedules can be delayed or dropped and public-repo
schedules can disable after 60 days of inactivity. A nightly cron alone is not a
freshness guarantee. This repository's `coverage.yml` reports scheduled-workflow
health across public repositories, including missing adoption. Subscribe to its
failure notifications and check its own freshness; this is not an independently
hosted scheduler watchdog or a complete compliance audit.

## Licenses and third-party acknowledgments

Keep the project's license in each project. Preserve upstream copyright notices,
license texts, and applicable NOTICE content. Ship `THIRD_PARTY_NOTICES.txt` and
required license texts inside packages, images, or applications as appropriate,
as well as alongside release downloads. Keep Apache NOTICE requirements distinct
from a general dependency listing.

Generate attribution from resolved and distributed components, then review it.
ORT with ScanCode is the proposed attribution toolchain, pending project pilots;
the Trivy workflow does not yet generate legally sufficient notices. Unknown or
conflicting license metadata, advertising clauses, copyleft/source-delivery
obligations, and model-specific terms require review before release. Do not assume
the license of the top-level project covers third-party components.

## Release evidence and public presentation

Distribute artifact checksums, both SBOM formats, required notices, and build
provenance/attestations with releases. GitHub Actions artifacts are temporary
diagnostics, not durable release evidence. Bind attestations to exact distributed
digests; do not claim a SLSA level without verifying its requirements.
For private projects, keep all evidence in access-controlled storage. Do not
require GitHub's paid private attestation features; use standalone provenance
generation/signing where needed.

Each README links to the project security policy, supported releases, notices, and
SBOM downloads using the same terminology. OpenSSF Scorecard is a useful periodic
hygiene check, not a substitute for scans or a compliance certification.

## References

- [GitHub security features and availability](https://docs.github.com/en/code-security/getting-started/github-security-features)
- [GitHub default community files](https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/creating-a-default-community-health-file)
- [Trivy SBOMs](https://trivy.dev/docs/latest/supply-chain/sbom/)
- [OSS Review Toolkit](https://oss-review-toolkit.org/ort/)
