# Public and private repository baseline

This baseline defines adoption requirements, not current compliance.
Record the maintainer, supported releases, distributed artifacts, baseline commit SHA, and coverage gaps in each project's documentation.

## GitHub administration

Use standalone Trivy for dependency vulnerabilities.
Use local language analyzers, such as Bandit for Python.
GitHub Actions minutes and storage can incur charges.
The baseline requires no paid private-repository security services.
Optional GitHub features, such as Dependabot, complement the standalone scripts.
If you use Dependabot, configure it in each repository.

Protect default branches with required checks and review.
Assign code owners for workflows and policy.
Require maintainer 2FA.
Review access periodically.
Use organization settings where the plan supports them.
Otherwise, configure each repository separately.

Use least-privilege tokens and full commit SHA pins for Actions.
Keep untrusted pull-request code out of privileged `pull_request_target` jobs.
Keep release and attestation credentials out of dependency scans.
Prefer short-lived OIDC tokens over persistent release credentials.

## Inventory and SBOM coverage

Inventory resolved source dependencies, build dependencies, and distributed artifacts.
Identify development dependencies separately from runtime components.
Cover transitive dependencies, OS packages, bundled libraries, vendored code, fonts, model weights, and other assets.
Identify components that users download separately.
Record unknown origins.
Reconcile inventories with lockfiles, installed-package metadata, and build outputs.

For each release and supported platform, publish these records:

- `sbom.spdx.json` and `sbom.cdx.json`
- Source commit SHA and artifact digest
- Tool version and generation time

A nonempty SBOM alone proves neither inventory completeness nor license compliance.
Keep project-specific completeness checks.

## Vulnerabilities and nightly scans

Use Trivy as the primary scanner.
Retain other scanners where they add verified coverage.
Before scanner removal, compare inventories, findings, and VEX decisions for identical source commits and artifact digests.
Review each suppression separately.

Run source checks on pull requests and default-branch changes.
Run nightly scans with current vulnerability data for source and supported release artifacts.
Use each platform's immutable image manifest digest for release scans.
Scan distributed images directly, including older releases.

High/Critical findings fail the shared check, including unfixed findings.
Tool failures and empty inventories also fail the check.
Retain lower-severity findings for triage.
Review end-of-life base images and unsupported ecosystems even when scans report no CVEs.
Assign each finding an owner and remediation date based on exploitability and exposure.
Revoke leaked credentials.

Exceptions require a finding, package, version, evidence, owner, reviewer, expiry, and tracking reference.
VEX records an applicability conclusion, not a general waiver.
The shared workflow applies no suppressions.
Review an exception validation mechanism before you enable exceptions.

Track successful scans and failures across adopted repositories.
Flag successful scheduled runs more than 36 hours after their start.
GitHub can delay or drop scheduled runs.
GitHub can disable public-repository schedules after 60 days of inactivity.
`coverage.yml` checks scheduled-workflow health and missing adoption across public repositories.
Subscribe to its failure notifications.
Check its own freshness.
This reporter provides neither an independent scheduler watchdog nor a complete compliance audit.

## Licenses and third-party notices

Keep each project's license in that project.
Preserve upstream copyright notices, license texts, and applicable NOTICE content.
Include `THIRD_PARTY_NOTICES.txt` and required license texts in distributions and release downloads.
Apply Apache NOTICE requirements separately from dependency lists.
Generate attribution from resolved and distributed components.
Review the attribution before release.

Trivy does not generate legally sufficient notices.
Review unknown or conflicting licenses, advertising clauses, copyleft requirements, source-delivery obligations, and model terms before release.
The project license does not cover all third-party components.

## Release evidence

Distribute checksums, both SBOM formats, required notices, and build provenance or attestations with releases.
GitHub Actions artifacts provide temporary diagnostics, not durable release evidence.
Bind attestations to distributed artifact digests.
Verify SLSA requirements before you claim a SLSA level.
Keep private-project evidence in access-controlled storage.
Use standalone provenance generation and signatures where needed.
The baseline requires no paid private attestation features.

Link each README to the security policy, supported releases, notices, and SBOM downloads.
Use consistent terms for these links.
Use OpenSSF Scorecard for periodic hygiene checks only.
Scorecard replaces neither vulnerability scans nor compliance review.

## References

- [GitHub security features and availability](https://docs.github.com/en/code-security/getting-started/github-security-features)
- [GitHub default community files](https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/creating-a-default-community-health-file)
- [Trivy SBOMs](https://trivy.dev/docs/latest/supply-chain/sbom/)
