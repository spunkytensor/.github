"""Read-only scheduled-workflow health report; not a compliance certification.

Exactly one data source is required: ``--github-org ORG`` (read-only discovery)
or ``--input FILE`` (standalone, with no GitHub access).  The local JSON schema
is::

    {
      "repositories": [
        {
          "full_name": "owner/repository",
          "html_url": "https://example.invalid/repository",
          "checks": [
            {
              "path": ".github/workflows/security.yml",
              "state": "active",
              "latest": {
                "status": "completed",
                "conclusion": "success",
                "created_at": "2026-09-29T01:00:00Z",
                "html_url": "https://example.invalid/run"
              },
              "success": {
                "status": "completed",
                "conclusion": "success",
                "created_at": "2026-09-29T01:00:00Z"
              }
            }
          ]
        }
      ]
    }

``html_url`` is optional. ``latest`` and ``success`` may be null; otherwise all
shown run fields except ``html_url`` are required. Repositories and checks are
an explicit expected inventory; local mode never claims discovery. Empty
inventories, malformed values, and future run start timestamps fail closed.
``created_at`` is the scheduled run start time.
"""

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import sys
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


def _timestamp(value, now):
    if not isinstance(value, str):
        raise ValueError("created_at must be a timestamp string")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("created_at must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None:
        raise ValueError("created_at must include a timezone")
    if parsed > now:
        raise ValueError("run start timestamp is in the future")
    return parsed


def load_local(path, now):
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read input JSON: {error}") from error
    if not isinstance(data, dict) or not isinstance(data.get("repositories"), list):
        raise ValueError("input must contain a repositories array")
    if not data["repositories"]:
        raise ValueError("repositories must not be empty")
    repos = []
    for repo in data["repositories"]:
        if not isinstance(repo, dict) or not isinstance(repo.get("full_name"), str) or not repo["full_name"]:
            raise ValueError("each repository requires a non-empty full_name")
        checks = repo.get("checks")
        if not isinstance(checks, list) or not checks:
            raise ValueError(f"{repo['full_name']}: checks must be a non-empty array")
        normalized = {"full_name": repo["full_name"], "name": repo["full_name"].split("/")[-1],
                      "html_url": repo.get("html_url", "")}
        results = []
        for check in checks:
            if not isinstance(check, dict) or not isinstance(check.get("path"), str) or not check["path"]:
                raise ValueError(f"{repo['full_name']}: each check requires a non-empty path")
            if not isinstance(check.get("state"), str) or not check["state"]:
                raise ValueError(f"{repo['full_name']}: each check requires a state")
            for key in ("latest", "success"):
                run = check.get(key)
                if run is not None:
                    if not isinstance(run, dict) or not isinstance(run.get("status"), str) or "conclusion" not in run:
                        raise ValueError(f"{repo['full_name']} {check['path']}: malformed {key} run")
                    _timestamp(run.get("created_at"), now)
            success = check.get("success")
            if success is not None and (success["status"] != "completed" or success["conclusion"] != "success"):
                raise ValueError(f"{repo['full_name']} {check['path']}: success run is not successful")
            status = assess({"state": check["state"]}, check.get("latest"), success, now)
            latest = check.get("latest")
            url = latest.get("html_url", "") if latest else normalized["html_url"]
            results.append((check["path"], status, url))
        repos.append((normalized, results))
    return repos


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--github-org", help="read repositories from this GitHub organization")
    source.add_argument("--input", metavar="JSON", help="use an explicit standalone JSON inventory")
    parser.add_argument("--visibility", choices=("public", "private", "all"), default="public",
                        help="GitHub repository visibility (default: public; private/all require gh authentication)")
    args = parser.parse_args(argv)
    now = dt.datetime.now(dt.timezone.utc)
    if args.input and args.visibility != "public":
        parser.error("--visibility is only valid with --github-org")
    try:
        if args.input:
            inspected = load_local(args.input, now)
            scope = "Explicit local repository/check inventory; no discovery performed."
            title = "Repository scan freshness"
        else:
            pages = api(f"orgs/{quote(args.github_org, safe='')}/repos?type={args.visibility}&per_page=100", paginate=True)
            repos = sorted((repo for page in pages for repo in page if not repo["archived"]),
                           key=lambda repo: repo["full_name"])
            inspected = [(repo, inspect_repository(repo, now)) for repo in repos]
            scope = f"Active {args.visibility} repositories discovered through GitHub."
            if args.visibility != "public":
                scope += " Private visibility requires appropriately scoped gh authentication."
            title = f"{args.visibility.capitalize()}-repository scan freshness"
    except (ValueError, subprocess.CalledProcessError, KeyError, TypeError) as error:
        print(f"ERROR: scan freshness could not be evaluated: {error}", file=sys.stderr)
        return 1
    lines = [f"# {title}", "", f"Checked at {now.isoformat()}. {scope}", "",
             "This reports scheduled workflow health, not inventory completeness,",
             "license compliance, or a guarantee that CVEs are absent. Content-only",
             "profiles run content checks instead of dependency scans.", "",
             "| Repository | Workflow | Scheduled check |", "| --- | --- | --- |"]
    failures = 0
    for repo, results in inspected:
        for path, status, url in results:
            failures += not status.startswith("OK:")
            label = f"[{repo['name']}]({url})" if url else repo["name"]
            lines.append(f"| {label} | `{path}` | {status} |")
    if not inspected:
        failures += 1
        lines.append("\nERROR: no repositories were returned; coverage is unknown.")
    report = "\n".join(lines) + "\n"
    print(report)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as summary:
            summary.write(report)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
