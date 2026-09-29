"""Run with: uv run --with pyyaml python -m unittest discover -s tests -v."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/trivy.yml"
STEPS = yaml.safe_load(WORKFLOW.read_text())["jobs"]["scan"]["steps"]


class WorkflowTests(unittest.TestCase):
    def run_step(self, name, directory, **env):
        script = next(step["run"] for step in STEPS if step["name"] == name)
        return subprocess.run(
            ["bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", script],
            cwd=directory,
            env={**os.environ, **env},
            capture_output=True,
            text=True,
        )

    def test_image_identity(self):
        cases = [
            ("", 0),
            ("ghcr.io/spunkytensor/example@sha256:" + "a" * 64, 0),
            ("ghcr.io/spunkytensor/example:latest", 1),
            ("ghcr.io/spunkytensor/example@sha256:" + "a" * 63, 1),
            ("ghcr.io/spunkytensor/example@sha256:" + "a" * 65, 1),
            ("example\ninjected@sha256:" + "a" * 64, 1),
        ]
        with tempfile.TemporaryDirectory() as directory:
            for image, expected in cases:
                with self.subTest(image=image):
                    result = self.run_step(
                        "Validate image identity", directory,
                        IMAGE_REF=image, RUNNER_TEMP=directory,
                        GITHUB_ENV=str(Path(directory) / "env"),
                    )
                    self.assertEqual(result.returncode, expected, result.stderr)

    def test_gate_boundaries(self):
        package = {"Name": "example", "Version": "1.0"}
        cases = [
            ("empty", {"Results": []}, 1),
            ("missing-results", {}, 1),
            ("packages-without-findings", {"Packages": [package]}, 0),
            ("medium", {"Packages": [package], "Vulnerabilities": [{"Severity": "MEDIUM"}]}, 0),
            ("high-unfixed", {"Packages": [package], "Vulnerabilities": [{"Severity": "HIGH", "FixedVersion": ""}]}, 1),
            ("critical-fixed", {"Packages": [package], "Vulnerabilities": [{"Severity": "CRITICAL", "FixedVersion": "2.0"}]}, 1),
        ]
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "trivy.json"
            for name, result, expected in cases:
                with self.subTest(name=name):
                    document = result if name in ("empty", "missing-results") else {"Results": [result]}
                    report.write_text(json.dumps(document))
                    execution = self.run_step(
                        "Reject empty inventories and High or Critical findings",
                        directory, REPORT_DIR=directory,
                    )
                    self.assertEqual(execution.returncode, expected, execution.stderr)
            report.write_text("invalid json")
            execution = self.run_step(
                "Reject empty inventories and High or Critical findings",
                directory, REPORT_DIR=directory,
            )
            self.assertNotEqual(execution.returncode, 0)

    def test_evidence_is_retained_on_failure(self):
        upload = next(step for step in STEPS if step["name"] == "Retain evidence even when the gate fails")
        self.assertEqual(upload["if"], "always()")
        self.assertEqual(upload["with"]["if-no-files-found"], "error")


if __name__ == "__main__":
    unittest.main()
