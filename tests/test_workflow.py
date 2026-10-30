import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]


class WorkflowTests(unittest.TestCase):
    def test_gate_boundaries(self):
        package = {"Name": "example", "Version": "1.0"}
        cases = [({}, 2), ({"Results": []}, 2),
                 ({"Results": [{"Packages": [package]}]}, 0)]
        for severity, expected in [("LOW", 0), ("MEDIUM", 0), ("HIGH", 1), ("CRITICAL", 1), ("invalid", 2)]:
            cases.append(({"Results": [{"Packages": [package], "Vulnerabilities": [
                {"Severity": severity, "FixedVersion": ""}]}]}, expected))
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "trivy.json"
            for document, expected in cases:
                report.write_text(json.dumps(document))
                result = subprocess.run(["python3", str(ROOT / "scripts/check_report.py"), str(report)], capture_output=True)
                self.assertEqual(result.returncode, expected, result.stderr)
            report.write_text("not json")
            self.assertNotEqual(subprocess.run(["python3", str(ROOT / "scripts/check_report.py"), str(report)], capture_output=True).returncode, 0)

    def test_scan_without_github_and_retains_failed_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "source"
            source.mkdir()
            binary = base / "trivy"
            binary.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
assert not any(k.startswith("GITHUB_") for k in os.environ)
assert "TRIVY_SEVERITY" not in os.environ
a = sys.argv[1:]
if os.environ.get("MOCK_FAIL"):
    sys.exit(3)
if a[0] == "version":
    print(json.dumps({"Version": os.environ.get("MOCK_VERSION", "0.76.1")}))
else:
    output = pathlib.Path(a[a.index("--output") + 1])
    if a[0] == "convert":
        output.write_text('{}')
    else:
        assert "--include-dev-deps" in a
        assert a[a.index("--ignorefile") + 1] == "/dev/null"
        output.write_text(json.dumps({"Results":[{"Packages":[{"Name":"test","Version":"1"}],"Vulnerabilities":[{"Severity":"HIGH"}]}]}))
''')
            binary.chmod(0o755)
            env = {key: value for key, value in os.environ.items() if not key.startswith("GITHUB_")}
            env.update(PATH=f"{base}:{env['PATH']}", TRIVY_SEVERITY="LOW")
            report = base / "reports"
            result = subprocess.run(["bash", str(ROOT / "scripts/scan.sh"), "source", str(source), str(report)], env=env, capture_output=True)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertTrue((report / "sbom.spdx.json").exists())
            self.assertTrue((report / "sbom.cdx.json").exists())
            self.assertEqual(subprocess.run(["sha256sum", "--check", "SHA256SUMS"], cwd=report, capture_output=True).returncode, 0)
            # Existing evidence cannot be reused or overwritten by a new scan.
            self.assertEqual(subprocess.run(["bash", str(ROOT / "scripts/scan.sh"), "source", str(source), str(report)], env=env, capture_output=True).returncode, 2)
            failed = base / "failed"
            result = subprocess.run(["bash", str(ROOT / "scripts/scan.sh"), "source", str(source), str(failed)], env={**env, "MOCK_FAIL": "1"}, capture_output=True)
            self.assertEqual(result.returncode, 3)
            self.assertFalse((failed / "SHA256SUMS").exists())
            # Reject any version other than the exact reviewed security release.
            for version in ["0.74.0", "0.76.0", "0.76.2"]:
                mismatch = base / f"version-{version}"
                result = subprocess.run(["bash", str(ROOT / "scripts/scan.sh"), "source", str(source), str(mismatch)], env={**env, "MOCK_VERSION": version}, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(json.loads((mismatch / "trivy-version.json").read_text())["Version"], version)
                self.assertFalse((mismatch / "trivy.json").exists())
                self.assertFalse((mismatch / "SHA256SUMS").exists())

    def test_image_identity(self):
        for image in ["example:latest", "example@sha256:" + "a" * 63, "example\ninjected@sha256:" + "a" * 64]:
            result = subprocess.run(["bash", str(ROOT / "scripts/scan.sh"), "image", image, "/unused"], capture_output=True)
            self.assertEqual(result.returncode, 2)

    def test_workflow_uses_pinned_tools_and_retains_evidence(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/trivy.yml").read_text())
        steps = workflow["jobs"]["scan"]["steps"]
        checkout = next(s for s in steps if s.get("name") == "Checkout shared tools")
        self.assertEqual(checkout["with"]["ref"], "${{ inputs.baseline-sha }}")
        trivy = next(s for s in steps if s.get("name") == "Install pinned Trivy")
        self.assertEqual(trivy["with"]["version"], "v0.76.1")
        self.assertFalse(trivy["with"]["cache"])
        upload = steps[-1]
        self.assertEqual(upload["if"], "always()")
        self.assertEqual(upload["with"]["if-no-files-found"], "error")
        text = (ROOT / ".github/workflows/public-repo-security.yml").read_text()
        self.assertNotIn("dependency-review-action", text)
        self.assertNotIn("codeql-action", text)
