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
attestations, GitHub settings, and organization-wide scan freshness monitoring
still need integration. Existing security checks must remain until replacement
coverage has been demonstrated.

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
`uv run --with pyyaml python -m unittest discover -s tests -v` (requires Bash and
jq). The tests execute the workflow's own validation/gate scripts against passing,
failing, empty, and malformed inputs. They do not replace live scanner or hosted
Actions integration tests.
