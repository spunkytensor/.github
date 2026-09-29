import datetime as dt
import unittest
from unittest.mock import patch

from scripts.check_scan_freshness import assess, inspect_repository, main


class FreshnessTests(unittest.TestCase):
    now = dt.datetime(2026, 9, 29, 12, tzinfo=dt.timezone.utc)
    workflow = {"state": "active"}

    def run_at(self, age, conclusion="success", status="completed"):
        return {"status": status, "conclusion": conclusion,
                "created_at": (self.now - age).isoformat()}

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

    def test_query_is_default_branch_and_scheduled_only(self):
        repo = {"full_name": "spunkytensor/example", "html_url": "https://github.com/spunkytensor/example", "default_branch": "release/main"}
        with patch("scripts.check_scan_freshness.api", side_effect=[
            [{"workflows": [{"path": ".github/workflows/public-repo-security.yml", "state": "active", "id": 42}]}],
            {"workflow_runs": []}, {"workflow_runs": []},
        ]) as api:
            _, status, _ = inspect_repository(repo, self.now)[0]
        self.assertTrue(status.startswith("MISSING:"))
        self.assertIn("branch=release%2Fmain&event=schedule", api.call_args_list[1].args[0])
        self.assertIn("status=success", api.call_args_list[2].args[0])

    def test_source_success_does_not_hide_separate_runtime_failure(self):
        repo = {"full_name": "spunkytensor/reel-video", "html_url": "https://github.com/spunkytensor/reel-video", "default_branch": "main"}
        success = {**self.run_at(dt.timedelta(hours=1)), "html_url": "https://github.com/example/success"}
        failed = {**self.run_at(dt.timedelta(minutes=30), conclusion="failure"), "html_url": "https://github.com/example/failure"}
        with patch("scripts.check_scan_freshness.api", side_effect=[
            [{"workflows": [
                {"path": ".github/workflows/public-repo-security.yml", "state": "active", "id": 42},
                {"path": ".github/workflows/security.yml", "state": "active", "id": 43},
            ]}],
            {"workflow_runs": [success]}, {"workflow_runs": [success]},
            {"workflow_runs": [failed]}, {"workflow_runs": [success]},
        ]):
            results = inspect_repository(repo, self.now)
        self.assertEqual(len(results), 2)
        self.assertTrue(results[0][1].startswith("OK:"))
        self.assertTrue(results[1][1].startswith("FAILED:"))

    def test_empty_organization_fails_closed(self):
        with patch("scripts.check_scan_freshness.api", return_value=[[]]), patch("builtins.print"), patch.dict("os.environ", {}, clear=True):
            self.assertEqual(main(), 1)


if __name__ == "__main__":
    unittest.main()
