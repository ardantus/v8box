#!/usr/bin/env bash
# ============================================================================
# CLOUDFLARE FEATURES TEST SCRIPT
# ============================================================================
# Tests Cloudflare-compatible features: Queues, Durable Objects, Cache, Rate Limit
# ============================================================================
set -euo pipefail

REDIS_URL="${REDIS_URL:-redis://localhost:6379}"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_DIR"

echo "=== Cloudflare Features Test Suite ==="
echo "Redis URL: ${REDIS_URL}"
echo ""

# Check dependencies
echo "== Checking dependencies =="
for cmd in deno redis-cli; do
  if ! command -v $cmd &> /dev/null; then
    echo "❌ $cmd not found"
    exit 1
  fi
  echo "✅ $cmd available"
done

# Check Redis connectivity
echo "== Checking Redis =="
if ! redis-cli -h "${REDIS_URL%%:*}" -p "${REDIS_URL##*:}" ping 2>/dev/null | grep -q PONG; then
  echo "❌ Redis not reachable"
  exit 1
fi
echo "✅ Redis reachable"

# Run tests
run_test() {
  local name="$1"
  local command="$2"

  echo "   Running: ${command}"
  if eval "$command" 2>&1 | tee /tmp/test_output.txt; then
    echo "   ✅ ${name}"
    return 0
  else
    echo "   ❌ ${name} FAILED"
    cat /tmp/test_output.txt
    return 1
  fi
}

echo "== Unit Tests =="
run_test "Queue enqueue" \
  "deno run --allow-env --allow-read --allow-write --allow-net queue.ts queue:send --queue=default --payload='{\"test\":\"hello\"}'"

run_test "Queue pull" \
  "deno run --allow-env --allow-read --allow-write --allow-net queue.ts queue:pull --queue=default"

run_test "Queue stats" \
  "deno run --allow-env --allow-read --allow-write --allow-net queue.ts queue:stats --queue=default"

run_test "Durable object create" \
  "deno run --allow-env --allow-read --allow-write --allow-net durable_objects.ts obj:create --name=test-obj"

run_test "Durable object get" \
  "deno run --allow-env --allow-read --allow-write --allow-net durable_objects.ts obj:get --name=test-obj"

run_test "Durable object list" \
  "deno run --allow-env --allow-read --allow-write --allow-net durable_objects.ts obj:list"

run_test "Cache set" \
  "deno run --allow-env --allow-read --allow-write --allow-net cache_purge.ts cache:set --key=test --value='{\"key\":\"value\"}'"

run_test "Cache get" \
  "deno run --allow-env --allow-read --allow-write --allow-net cache_purge.ts cache:get --key=test"

run_test "Cache purge by tag" \
  "deno run --allow-env --allow-read --allow-write --allow-net cache_purge.ts cache:purge --tag=default"

run_test "Rate limit check" \
  "deno run --allow-env --allow-read --allow-write --allow-net rate_limit.ts rate:check --ip=127.0.0.1 --rule=default"

echo ""
echo "🎉 All Cloudflare Features tests passed!"
