#!/usr/bin/env bash
# Run the CRS regression suite one category-directory at a time, with a
# hard wall-clock budget per category. If Kong locks up on a pathological
# test, we get to see which category, restart Kong, and move on rather
# than hanging the whole run.
#
# Output: results/categories/<DIR>.log per category, results/categories.txt
# summary.

set -uo pipefail  # no -e: we expect some categories to time out

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/results/categories"
mkdir -p "${RESULTS_DIR}"

# wall-clock budget per category (seconds). A healthy category should
# finish well under this; anything close to it is suspicious.
BUDGET="${BUDGET:-60}"

SUMMARY="${SCRIPT_DIR}/results/categories.txt"
: > "${SUMMARY}"

for dir in "${SCRIPT_DIR}"/tests/REQUEST-* "${SCRIPT_DIR}"/tests/RESPONSE-*; do
    [ -d "${dir}" ] || continue
    name="$(basename "${dir}")"
    log="${RESULTS_DIR}/${name}.log"

    echo "[$(date +%H:%M:%S)] ${name} (budget ${BUDGET}s) ..."

    # macOS `timeout` lives in coreutils as `gtimeout` — fall back to perl alarm
    if command -v gtimeout >/dev/null 2>&1; then
        gtimeout --kill-after=5 "${BUDGET}" \
            python3 "${SCRIPT_DIR}/start.py" --testfile "${dir}" --show-only-failed \
            > "${log}" 2>&1
    else
        perl -e "alarm ${BUDGET}; exec @ARGV" -- \
            python3 "${SCRIPT_DIR}/start.py" --testfile "${dir}" --show-only-failed \
            > "${log}" 2>&1
    fi
    rc=$?

    summary=$(tail -8 "${log}" | grep -E "Passed|Failed|Skipped|Total time" | tr '\n' ' ')
    if [ ${rc} -ne 0 ] && [ -z "${summary}" ]; then
        echo "  TIMEOUT / KILLED — Kong likely stuck on a pathological test."
        echo "${name}    TIMEOUT" >> "${SUMMARY}"

        echo "  restarting Kong ..."
        (cd "${SCRIPT_DIR}/.." && docker compose kill kong >/dev/null 2>&1
         docker compose up -d kong >/dev/null 2>&1)
        i=0
        until curl -fs --max-time 3 http://localhost:28001/ >/dev/null 2>&1; do
            sleep 2; i=$((i+1))
            [ $i -gt 40 ] && { echo "  Kong didn't come back, aborting."; exit 1; }
        done
        echo "  Kong back."
    else
        echo "  ${summary}"
        echo "${name}    ${summary}" >> "${SUMMARY}"
    fi
done

echo
echo "=== Summary ==="
cat "${SUMMARY}"
