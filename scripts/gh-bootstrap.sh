#!/usr/bin/env bash
# Create/update the repository labels from .github/labels.yml. Idempotent (`gh label create --force`).
# Usage: scripts/gh-bootstrap.sh [owner/repo]   (default: the repo of the current directory)
set -euo pipefail
[ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ] && { sed -n '2,3p' "$0" | sed 's/^# \?//'; exit 0; }
cd "$(dirname "$0")/.."
repo_args=()
[ -n "${1:-}" ] && repo_args=(--repo "$1")
python3 - <<'PY' | while IFS=$'\t' read -r name color desc; do
import re
for line in open(".github/labels.yml", encoding="utf-8"):
    m = re.match(r'- name: "?(.+?)"?\s*$', line)
    if m:
        name, color, desc = m.group(1), "", ""
    elif (m := re.match(r'\s+color: "?([0-9a-fA-F]{6})"?\s*$', line)):
        color = m.group(1)
    elif (m := re.match(r'\s+description: "?(.*?)"?\s*$', line)):
        print(f"{name}\t{color}\t{m.group(1)}")
PY
  echo "label: $name"
  gh label create "$name" --color "$color" --description "$desc" --force "${repo_args[@]}"
done
