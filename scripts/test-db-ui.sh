#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
HOST_HEADER="${HOST_HEADER:-admin.localhost}"
COOKIE_HEADER="${COOKIE_HEADER:-admin_session=authenticated}"
TEST_DB="${TEST_DB:-uitestdb}"
TEST_TABLE="${TEST_TABLE:-uitestitems}"

call_api() {
  local name="$1"
  local method="$2"
  local path="$3"
  local body="${4-}"

  local output_file
  output_file="/tmp/v8box_${name}.json"

  if [[ -n "$body" ]]; then
    curl -m 8 -sS \
      -H "Host: ${HOST_HEADER}" \
      -H "Cookie: ${COOKIE_HEADER}" \
      -H "Content-Type: application/json" \
      -X "${method}" "${BASE_URL}${path}" \
      -d "${body}" > "${output_file}"
  else
    curl -m 8 -sS \
      -H "Host: ${HOST_HEADER}" \
      -H "Cookie: ${COOKIE_HEADER}" \
      -X "${method}" "${BASE_URL}${path}" > "${output_file}"
  fi

  python3 - "$name" "$output_file" <<'PY'
import json
import sys

name = sys.argv[1]
path = sys.argv[2]

try:
    data = json.load(open(path))
except Exception as e:
    print(f"❌ {name}: invalid JSON ({e})")
    sys.exit(1)

if not data.get("success"):
    print(f"❌ {name}: {data.get('error')}")
    sys.exit(1)

print(f"✅ {name}")
PY
}

echo "== V8Box DB UI smoke test =="
echo "BASE_URL=${BASE_URL}"
echo "HOST_HEADER=${HOST_HEADER}"
echo

call_api "list_databases" "GET" "/admin/database/databases"
call_api "create_database" "POST" "/admin/database/databases" "{\"name\":\"${TEST_DB}\"}"
call_api "list_tables" "GET" "/admin/database/databases/${TEST_DB}/tables"
call_api "create_table" "POST" "/admin/database/databases/${TEST_DB}/tables" "{\"tableName\":\"${TEST_TABLE}\",\"columns\":[{\"name\":\"id\",\"type\":\"INTEGER\",\"primaryKey\":true,\"autoIncrement\":true},{\"name\":\"name\",\"type\":\"TEXT\",\"nullable\":false},{\"name\":\"status\",\"type\":\"TEXT\",\"default\":\"active\"}]}"
call_api "insert_row" "POST" "/admin/database/databases/${TEST_DB}/tables/${TEST_TABLE}/rows" "{\"data\":{\"name\":\"row-1\",\"status\":\"active\"}}"
call_api "read_rows" "GET" "/admin/database/databases/${TEST_DB}/tables/${TEST_TABLE}/rows?limit=50&order=DESC"
call_api "search_rows" "POST" "/admin/database/databases/${TEST_DB}/tables/${TEST_TABLE}/rows/search" "{\"where\":\"status = ?\",\"whereArgs\":[\"active\"],\"limit\":50}"
call_api "update_rows_where" "PUT" "/admin/database/databases/${TEST_DB}/tables/${TEST_TABLE}/rows" "{\"data\":{\"status\":\"inactive\"},\"where\":\"name = ?\",\"whereArgs\":[\"row-1\"]}"
call_api "delete_rows_where" "DELETE" "/admin/database/databases/${TEST_DB}/tables/${TEST_TABLE}/rows" "{\"where\":\"name = ?\",\"whereArgs\":[\"row-1\"]}"
call_api "query_per_db" "POST" "/admin/database/query/${TEST_DB}" "{\"query\":\"SELECT name FROM sqlite_master WHERE type = 'table'\"}"
call_api "query_global" "POST" "/admin/database/query/global" "{\"query\":\"SELECT 1 AS ok\"}"
call_api "delete_table" "DELETE" "/admin/database/databases/${TEST_DB}/tables/${TEST_TABLE}"
call_api "delete_database" "DELETE" "/admin/database/databases/${TEST_DB}"

echo
echo "🎉 Semua test database UI lulus"
