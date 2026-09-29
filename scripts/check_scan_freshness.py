"""Read-only scheduled-workflow health report; not a compliance certification."""

import datetime as dt
import json
import os
from pathlib import Path
import subprocess
from urllib.parse import quote


WORKFLOW_PATH = ".github/workflows/public-repo-security.yml"
MAX_AGE = dt.timedelta(hours=36)
# Retained nightly checks complement the shared caller. A clean source scan must
# not hide a failed RustSec audit or runtime-image scan in a separate workflow.
EXTRA_WORKFLOWS = {
    "spunkytensor/reel-maestro": [".github/workflows/security.yml", ".github/workflows/container.yml"],
    "spunkytensor/reel-video": [".github/workflows/security.yml"],
}


def api(endpoint, paginate=False):
    command = ["gh", "api", endpoint]
    if paginate:
        command += ["--paginate", "--slurp"]
    return json.loads(subprocess.check_output(command, text=True))


def assess(workflow, latest, success, now):
    if workflow is None:
        return "MISSING: standardized workflow is not registered"
    if workflow["state"] != "active":
        return f"DISABLED: {workflow['state']}"
    if latest and latest["status"] == "completed" and latest["conclusion"] != "success":
        return f"FAILED: latest scheduled run concluded {latest['conclusion']}"
    if not success:
        return "MISSING: no successful scheduled run"
    # Use start/creation time, not completion time: a long-running stale scan
    # must not become fresh merely because it finally completed.
    started = dt.datetime.fromisoformat(success["created_at"].replace("Z", "+00:00"))
    if now - started > MAX_AGE:
        return "STALE: last successful scheduled run started over 36 hours ago"
    if latest and latest["status"] != "completed":
        return "OK: previous successful scan is fresh; next run is pending"
    return "OK: successful scheduled run within 36 hours"


def inspect_workflow(repo, workflow, now):
    name = repo["full_name"]
    if not workflow or workflow["state"] != "active":
        return assess(workflow, None, None, now), repo["html_url"] + "/actions"
    branch = quote(repo["default_branch"], safe="")
    endpoint = (f"repos/{name}/actions/workflows/{workflow['id']}/runs"
                f"?branch={branch}&event=schedule&per_page=1")
    latest_runs = api(endpoint)["workflow_runs"]
    successful_runs = api(endpoint + "&status=success")["workflow_runs"]
    latest = latest_runs[0] if latest_runs else None
    success = successful_runs[0] if successful_runs else None
    return assess(workflow, latest, success, now), (
        latest["html_url"] if latest else repo["html_url"] + "/actions"
    )


def inspect_repository(repo, now):
    pages = api(f"repos/{repo['full_name']}/actions/workflows?per_page=100", paginate=True)
    workflows = {workflow["path"]: workflow for page in pages for workflow in page["workflows"]}
    required = [WORKFLOW_PATH, *EXTRA_WORKFLOWS.get(repo["full_name"], [])]
    return [(path, *inspect_workflow(repo, workflows.get(path), now)) for path in required]


def main():
    now = dt.datetime.now(dt.timezone.utc)
    pages = api("orgs/spunkytensor/repos?type=public&per_page=100", paginate=True)
    repos = sorted((repo for page in pages for repo in page if not repo["archived"]),
                   key=lambda repo: repo["full_name"])
    lines = ["# Public-repository scan freshness", "",
             f"Checked at {now.isoformat()}. Active public repositories only.", "",
             "This reports scheduled workflow health, not inventory completeness,",
             "license compliance, or a guarantee that CVEs are absent. Content-only",
             "profiles run content checks instead of dependency scans.", "",
             "| Repository | Workflow | Scheduled check |", "| --- | --- | --- |"]
    failures = 0
    for repo in repos:
        try:
            results = inspect_repository(repo, now)
        except (subprocess.CalledProcessError, KeyError, ValueError):
            results = [("unknown", "ERROR: repository status could not be verified", repo["html_url"])]
        for path, status, url in results:
            failures += not status.startswith("OK:")
            lines.append(f"| [{repo['name']}]({url}) | `{path}` | {status} |")
    if not repos:
        failures += 1
        lines.append("\nERROR: no public repositories were returned; coverage is unknown.")
    report = "\n".join(lines) + "\n"
    print(report)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as summary:
            summary.write(report)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
