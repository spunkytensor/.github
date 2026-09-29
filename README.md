# Spunky Tensor open-source baseline

Shared community guidance and reusable security automation for repositories owned
by [Spunky Tensor](https://github.com/spunkytensor).

## Adoption status

This is the initial baseline, not a claim that every repository complies with it.
The reusable Trivy workflow inventories source dependencies or a public container
image pinned by digest, produces SPDX and CycloneDX SBOMs, and fails on High or
Critical vulnerabilities, including those without fixes. It retains all severities
in its JSON report and rejects an empty package inventory.

Project-specific inventory completeness checks, notice generation, release
attestations, and GitHub settings still need integration. Existing security checks
must remain until replacement coverage has been demonstrated. The read-only
organization freshness report detects missing, disabled, failed, and stale
scheduled checks; it does not certify complete baseline compliance.

## What is shared

- `CONTRIBUTING.md` and `SUPPORT.md` are GitHub community-file defaults. Local
  project files take precedence. Defaults do not become part of project archives.
- `.github/workflows/trivy.yml` is explicitly called by participating repositories;
  creating this repository does not enable scans elsewhere.
- [The baseline](docs/baseline.md) defines security, inventory, attribution, and
  release requirements.
- [Onboarding](docs/onboarding.md) explains caller workflows and settings.

A default `SECURITY.md` is intentionally pending confirmation of a working private
reporting route. Do not replace existing project security policies in the meantime.
Project licenses and legal notices remain project-local; this repository does not
relicense any other project.

## Maintaining the baseline

Review shared workflow changes before publication. Callers pin full commit SHAs;
updates propagate through reviewed update PRs, not mutable `main` references.
Dependabot updates this repository's action pins. The explicitly pinned Trivy
binary version must also be reviewed and updated here.

Use the same check name, **Spunky Tensor security**, in caller workflows. Publish
only evidence-backed coverage claims. Do not add a passing badge until the caller
is enabled and its scans have succeeded.

Validate workflow changes with `actionlint .github/workflows/trivy.yml` and
`uv run --with-requirements requirements.txt python -m unittest discover -s tests -v` (requires Bash and
jq). The tests execute the workflow's own validation/gate scripts against passing,
failing, empty, and malformed inputs. They do not replace live scanner or hosted
Actions integration tests.

## This repository's security profile

Maintainers: Spunky Tensor organization maintainers. Fixes target `main`; older
workflow pins are not independently maintained, so consumers must review updates.
No response-time or security-support SLA is promised.

`.github/workflows/public-repo-security.yml` tests this repository's current shared
workflow, inventories the pinned Python test dependency, runs dependency review
on PRs, and analyzes Python with CodeQL. Scheduled checks run at 10:07 UTC daily.
The source SBOM covers test dependencies, not every tool on the hosted runner.
No compiled application or container is distributed here. The source archive
contains [LICENSE](LICENSE) and [third-party notices](THIRD_PARTY_NOTICES.txt).

`.github/workflows/coverage.yml` checks every non-archived public `spunkytensor`
repository at 12:17 UTC. It requires the standardized caller path
`.github/workflows/public-repo-security.yml` and a successful **scheduled** run
within 36 hours. PR/manual successes cannot hide a broken schedule. Its Actions
summary links to relevant runs and exits nonzero for gaps, including repositories
whose adoption PR has not merged yet. Failed runs notify subscribed maintainers
through normal GitHub Actions notifications; it does not send external alerts or
write issues. The reporter itself is subject to GitHub schedule delays/inactivity;
maintainers must watch its freshness too.

Private reporting, branch protection, required-check selection, CodeQL enablement,
secret protection, and access/2FA enforcement remain administrator work. Report
security concerns privately using a confirmed maintainer channel; if no channel is
available, request one without publishing vulnerability details. Do not mistake
this pending private-reporting setup for an established confidential intake route.

## License

Copyright 2026 Spunky Tensor. This repository's original material is licensed
under Apache-2.0; third-party material retains its own license. This does not
change the license of any repository that consumes these workflows or defaults.
