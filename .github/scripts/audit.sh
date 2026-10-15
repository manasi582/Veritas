#!/bin/bash
# Fails if a Python dependency has a known vulnerability that is not listed (with a reason) in
# .github/security/audit-ignore.txt. Usage: audit.sh <requirements.txt> [more files...]
set -e
IGNORES=()
while read -r id rest; do
  case "$id" in ""|\#*) continue;; esac
  [ -n "$rest" ] || { echo "audit-ignore.txt: $id has no reason"; exit 1; }
  IGNORES+=(--ignore-vuln "$id")
done < "$(dirname "$0")/../security/audit-ignore.txt"
python -m venv /tmp/auditenv >/dev/null
/tmp/auditenv/bin/pip install -q pip-audit
STATUS=0
for req in "$@"; do
  echo "== $req"
  /tmp/auditenv/bin/pip-audit -r "$req" "${IGNORES[@]}" --progress-spinner off || STATUS=1
done
exit $STATUS
