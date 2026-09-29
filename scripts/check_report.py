"""Validate a Trivy JSON inventory and fail on High/Critical vulnerabilities."""

import json
import sys
from pathlib import Path


def check(report):
    results = report["Results"]
    if not isinstance(results, list):
        raise ValueError("Results must be an array")
    packages = 0
    findings = 0
    for result in results:
        inventory = result.get("Packages", [])
        vulnerabilities = result.get("Vulnerabilities", [])
        if not isinstance(inventory, list) or not isinstance(vulnerabilities, list):
            raise ValueError("Invalid package or vulnerability array")
        for package in inventory:
            if not package.get("Name") or not package.get("Version"):
                raise ValueError("Package identity is missing")
        packages += len(inventory)
        for vulnerability in vulnerabilities:
            severity = vulnerability["Severity"]
            if severity not in {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                raise ValueError("Invalid severity")
            findings += severity in {"HIGH", "CRITICAL"}
    if not packages:
        raise ValueError("No packages detected; inventory coverage must be reviewed")
    print(f"Packages: {packages}; High/Critical findings: {findings}")
    return 1 if findings else 0


def main():
    try:
        return check(json.loads(Path(sys.argv[1]).read_text()))
    except (OSError, ValueError, KeyError, TypeError, AttributeError, IndexError) as error:
        print(f"Invalid scan report: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
