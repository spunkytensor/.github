import datetime as dt
import json
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from scripts.check_scan_freshness import assess, inspect_repository, main


class FreshnessTests(unittest.TestCase):
    now = dt.datetime(2026, 9, 29, 12, tzinfo=dt.timezone.utc)
    workflow = {"state": "active"}

    def run_at(self, age, conclusion="success", status="completed"):
        return {"status": status, "conclusion": conclusion,
                "created_at": (self.now - age).isoformat()}

    def run_local(self, data):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as source:
            json.dump(data, source)
            source.flush()
            with patch("scripts.check_scan_freshness.api") as api, \
                    patch("builtins.print") as output, patch.dict("os.environ", {}, clear=True):
                result = main(["--input", source.name])
        api.assert_not_called()
        return result, "\n".join(str(call.args[0]) for call in output.call_args_list)

    def test_threshold_uses_scan_start_not_completion(self):
        fresh = self.run_at(dt.timedelta(hours=36))
        self.assertTrue(assess(self.workflow, fresh, fresh, self.now).startswith("OK:"))
        stale = self.run_at(dt.timedelta(hours=36, seconds=1))
        stale["updated_at"] = self.now.isoformat()
        self.assertTrue(assess(self.workflow, stale, stale, self.now).startswith("STALE:"))

    def test_recent_success_does_not_hide_new_failure_or_disabled_workflow(self):
        success = self.run_at(dt.timedelta(hours=2))
        failed = self.run_at(dt.timedelta(hours=1), conclusion="failure")
        self.assertTrue(assess(self.workflow, failed, success, self.now).startswith("FAILED:"))
        self.assertTrue(assess({"state": "disabled_inactivity"}, success, success, self.now).startswith("DISABLED:"))

    def test_pending_run_does_not_mask_staleness(self):
        queued = self.run_at(dt.timedelta(minutes=1), conclusion=None, status="queued")
        stale = self.run_at(dt.timedelta(hours=37))
        self.assertTrue(assess(self.workflow, queued, stale, self.now).startswith("STALE:"))
        self.assertTrue(assess(self.workflow, queued, None, self.now).startswith("MISSING:"))
        fresh = self.run_at(dt.timedelta(hours=1))
        self.assertTrue(assess(self.workflow, queued, fresh, self.now).startswith("OK:"))

    def test_missing_caller_is_not_confused_with_reusable_workflow(self):
        repo = {"full_name": "spunkytensor/example", "html_url": "https://github.com/spunkytensor/example"}
        with patch("scripts.check_scan_freshness.api", return_value=[{"workflows": [
            {"path": ".github/workflows/trivy.yml", "state": "active"}
        ]}]):
            _, status, _ = inspect_repository(repo, self.now)[0]
        self.assertTrue(status.startswith("MISSING:"))

    def github_runs(self, runs):
        """Fake gh api: workflow list, then runs keyed by (path, event)."""
        def api(endpoint, paginate=False):
            if endpoint.endswith("workflows?per_page=100"):
                return [{"workflows": [{"path": path, "state": "active", "id": path} for path in {p for p, _ in runs}]}]
            workflow_id = endpoint.split("/actions/workflows/")[1].split("/runs?")[0]
            query = parse_qs(urlsplit(endpoint).query)
            found = [run for run in runs.get((workflow_id, query["event"][0]), [])
                     if query.get("status") != ["success"] or run["conclusion"] == "success"]
            return {"workflow_runs": found[:1]}
        return api

    def test_query_is_default_branch_and_scheduled_or_manual_only(self):
        repo = {"full_name": "spunkytensor/example", "html_url": "https://github.com/spunkytensor/example", "default_branch": "release/main"}
        with patch("scripts.check_scan_freshness.api", side_effect=[
            [{"workflows": [{"path": ".github/workflows/public-repo-security.yml", "state": "active", "id": 42}]}],
            *[{"workflow_runs": []}] * 4,
        ]) as api:
            _, status, _ = inspect_repository(repo, self.now)[0]
        self.assertTrue(status.startswith("MISSING:"))
        queries = [call.args[0] for call in api.call_args_list[1:]]
        self.assertTrue(all("branch=release%2Fmain" in query for query in queries))
        self.assertEqual(sorted(parse_qs(urlsplit(query).query)["event"][0] for query in queries),
                         ["schedule", "schedule", "workflow_dispatch", "workflow_dispatch"])
        self.assertEqual(sum("status=success" in query for query in queries), 2)

    def test_newer_manual_run_decides_status_in_either_direction(self):
        repo = {"full_name": "spunkytensor/example", "html_url": "https://github.com/spunkytensor/example", "default_branch": "main"}
        path = ".github/workflows/public-repo-security.yml"
        old_failure = {**self.run_at(dt.timedelta(hours=9), conclusion="failure"), "html_url": "https://github.com/example/schedule"}
        old_success = {**self.run_at(dt.timedelta(hours=9)), "html_url": "https://github.com/example/schedule"}
        manual_success = {**self.run_at(dt.timedelta(hours=1)), "html_url": "https://github.com/example/manual"}
        manual_failure = {**manual_success, "conclusion": "failure"}
        cases = [(old_failure, manual_success, "OK:"), (old_success, manual_failure, "FAILED:")]
        for scheduled, manual, expected in cases:
            with self.subTest(expected=expected):
                runs = {(path, "schedule"): [scheduled], (path, "workflow_dispatch"): [manual]}
                with patch("scripts.check_scan_freshness.api", side_effect=self.github_runs(runs)):
                    _, status, url = inspect_repository(repo, self.now)[0]
                self.assertTrue(status.startswith(expected), status)
                self.assertEqual(url, "https://github.com/example/manual")

    def test_source_success_does_not_hide_separate_runtime_failure(self):
        repo = {"full_name": "spunkytensor/reel-video", "html_url": "https://github.com/spunkytensor/reel-video", "default_branch": "main"}
        success = {**self.run_at(dt.timedelta(hours=1)), "html_url": "https://github.com/example/success"}
        failed = {**self.run_at(dt.timedelta(minutes=30), conclusion="failure"), "html_url": "https://github.com/example/failure"}
        runs = {(".github/workflows/public-repo-security.yml", "schedule"): [success],
                (".github/workflows/security.yml", "schedule"): [failed, success]}
        with patch("scripts.check_scan_freshness.api", side_effect=self.github_runs(runs)):
            results = inspect_repository(repo, self.now)
        self.assertEqual(len(results), 2)
        self.assertTrue(results[0][1].startswith("OK:"))
        self.assertTrue(results[1][1].startswith("FAILED:"))

    def test_empty_organization_fails_closed(self):
        with patch("scripts.check_scan_freshness.api", return_value=[[]]), patch("builtins.print"), patch.dict("os.environ", {}, clear=True):
            self.assertEqual(main(["--github-org", "spunkytensor"]), 1)

    def test_local_mode_is_standalone_and_fresh_boundary_passes(self):
        now = dt.datetime.now(dt.timezone.utc)
        run = {"status": "completed", "conclusion": "success",
               "created_at": (now - dt.timedelta(hours=35)).isoformat()}
        data = {"repositories": [{"full_name": "private/example", "checks": [
            {"path": "security.yml", "state": "active", "latest": run, "success": run}
        ]}]}
        result, report = self.run_local(data)
        self.assertEqual(result, 0)
        self.assertIn("OK: successful scheduled or manual run within 36 hours", report)
        self.assertIn("no discovery performed", report)

    def test_local_failure_and_missing_checks_fail_closed(self):
        now = dt.datetime.now(dt.timezone.utc)
        success = {"status": "completed", "conclusion": "success",
                   "created_at": (now - dt.timedelta(hours=1)).isoformat()}
        failed = {**success, "conclusion": "failure"}
        data = {"repositories": [{"full_name": "owner/example", "checks": [
            {"path": "failed.yml", "state": "active", "latest": failed, "success": success},
            {"path": "missing.yml", "state": "active", "latest": None, "success": None},
        ]}]}
        result, report = self.run_local(data)
        self.assertEqual(result, 1)
        self.assertIn("FAILED:", report)
        self.assertIn("MISSING:", report)

    def test_local_empty_malformed_and_future_inputs_fail_closed(self):
        future = {"status": "completed", "conclusion": "success",
                  "created_at": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)).isoformat()}
        invalid = [
            {"repositories": []},
            {"repositories": [{"full_name": "owner/example", "checks": []}]},
            {"repositories": [{"full_name": "owner/example", "checks": [
                {"path": "security.yml", "state": "active", "latest": future, "success": future}
            ]}]},
        ]
        for data in invalid:
            with self.subTest(data=data):
                result, _ = self.run_local(data)
                self.assertEqual(result, 1)


if __name__ == "__main__":
    unittest.main()
