#!/usr/bin/env bash
# End-to-end bench: run the full CRS regression suite twice — once with the
# in-repo coreruleset_fix.lua layer active, once with it stubbed out — and
# diff the per-test pass/fail lines. The diff is the cost (in CRS detection
# coverage) we're paying for the operational FP-control layer.
#
# Requires: docker compose stack up, `configure-kong.sh` already run,
# `fetch-tests.sh` already run.
#
# Output:
#   results/with_fix.log
#   results/without_fix.log
#   results/diff.log

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/results"
mkdir -p "${RESULTS_DIR}"

run_suite() {
    local label="$1"
    echo "[$(date +%H:%M:%S)] Running suite (${label}) ..."
    python3 "${SCRIPT_DIR}/start.py" \
        --testfile "${SCRIPT_DIR}/tests/" \
        --show-only-failed \
        > "${RESULTS_DIR}/${label}.log" 2>&1
    echo "[$(date +%H:%M:%S)] Done. Tail:"
    tail -6 "${RESULTS_DIR}/${label}.log"
    echo
}

echo "=== Phase 1: suite WITH coreruleset_fix.lua active (current default) ==="
run_suite with_fix

echo "=== Phase 2: swap coreruleset_fix.lua → empty stub, restart Kong ==="
"${SCRIPT_DIR}/toggle-crs-fix.sh" off
docker compose restart kong
# Wait until Admin API is back and the worker has re-parsed the rules.
echo -n "Waiting for Kong Admin ... "
until curl -fs http://localhost:28001/ >/dev/null 2>&1; do sleep 2; done
echo "ready."
echo "Letting the worker warm up CRS rules (one warmup request) ..."
curl -fs -o /dev/null -H "Host: karna-test" -H "X-Karna-Test: true" \
    http://localhost:28000/ || true
sleep 3

echo "=== Phase 3: suite WITHOUT coreruleset_fix.lua ==="
run_suite without_fix

echo "=== Phase 4: restore coreruleset_fix.lua + restart ==="
"${SCRIPT_DIR}/toggle-crs-fix.sh" on
docker compose restart kong
until curl -fs http://localhost:28001/ >/dev/null 2>&1; do sleep 2; done
echo "Restored."

echo
echo "=== Phase 5: diff ==="
{
    echo "# Tests that PASS with the fix layer but FAIL without it"
    echo "# (= rules that coreruleset_fix has unbroken — operational wisdom)"
    diff "${RESULTS_DIR}/with_fix.log" "${RESULTS_DIR}/without_fix.log" \
        | grep -E "^< .*passed|^> .*failed" || true
    echo
    echo "# Tests that FAIL with the fix layer but PASS without it"
    echo "# (= detection coverage paid as the cost of FP control)"
    diff "${RESULTS_DIR}/with_fix.log" "${RESULTS_DIR}/without_fix.log" \
        | grep -E "^< .*failed|^> .*passed" || true
} > "${RESULTS_DIR}/diff.log"

echo "Diff written to ${RESULTS_DIR}/diff.log"
echo
echo "Aggregate numbers:"
for f in with_fix without_fix; do
    grep -E "✅|❌|🚫" "${RESULTS_DIR}/${f}.log" | sed "s/^/  [${f}] /"
done
