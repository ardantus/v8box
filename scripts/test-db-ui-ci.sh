#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="${LOG_FILE:-/tmp/v8box-db-ui-ci.log}"

if bash scripts/test-db-ui.sh >"${LOG_FILE}" 2>&1; then
  echo "DB_UI_CI:PASS"
  exit 0
fi

echo "DB_UI_CI:FAIL"
echo "--- Last 80 lines ---"
tail -n 80 "${LOG_FILE}" || true
exit 1
