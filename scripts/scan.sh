#!/usr/bin/env bash
# Standalone source/image inventory and CVE gate. Requires Trivy 0.74.0, jq,
# Python 3 and sha256sum. No GitHub API or token is used.
set -euo pipefail
if [[ $# != 3 || ( "$1" != source && "$1" != image ) ]]; then
  echo 'Usage: bash scan.sh source PATH REPORT_DIR | image NAME@sha256:DIGEST REPORT_DIR' >&2
  exit 2
fi
mode=$1
subject=$2
commit=''
report=$(realpath -m "$3")
if [[ "$mode" == image && ! "$subject" =~ ^[^[:space:]]+@sha256:[a-f0-9]{64}$ ]]; then
  echo 'Image must be pinned by sha256 digest' >&2
  exit 2
fi
if [[ "$mode" == source ]]; then
  subject=$(realpath -e "$subject")
  [[ -d "$subject" ]] || exit 2
  if git -C "$subject" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    commit=$(git -C "$subject" rev-parse HEAD)
  fi
  case "$report/" in "$subject/"*) echo 'Reports must be outside the scanned source' >&2; exit 2;; esac
fi
if [[ -e "$report" ]]; then
  echo 'Report directory must not already exist; use a unique directory for each scan' >&2
  exit 2
fi
# Ignore TRIVY_* policy overrides from the calling environment. Registry login
# can use the caller's Docker credential store (never place credentials in refs).
for variable in ${!TRIVY_@}; do unset "$variable"; done
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export TRIVY_CACHE_DIR="$work/cache"
mkdir -p "$report"
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$work"
trivy version --format json > "$report/trivy-version.json"
jq -e '.Version == "0.74.0"' "$report/trivy-version.json" >/dev/null
jq -n --arg kind "$mode" --arg subject "$subject" --arg commit "$commit" \
  --arg generated "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{kind:$kind, subject:$subject, event_commit:$commit, generated_at:$generated}' > "$report/subject.json"
target=(fs --include-dev-deps "$subject")
if [[ "$mode" == image ]]; then target=(image --image-src remote "$subject"); fi
trivy "${target[@]}" --scanners vuln --list-all-pkgs \
  --ignorefile /dev/null --ignore-unfixed=false --exit-code 0 \
  --format json --output "$report/trivy.json"
trivy convert --format spdx-json --output "$report/sbom.spdx.json" "$report/trivy.json"
trivy convert --format cyclonedx --output "$report/sbom.cdx.json" "$report/trivy.json"
(cd "$report" && sha256sum ./*.json > SHA256SUMS)
python3 "$script_dir/check_report.py" "$report/trivy.json"
