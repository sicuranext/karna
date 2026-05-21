#!/usr/bin/env bash
# Toggle the in-repo CRS-fix layer on/off for benchmarking.
#
# `off` swaps kong/plugins/karna/rules/coreruleset_fix.lua with an empty
# stub (preserves the file load, removes the entries it returns to the
# engine). `on` restores the original. The backup lives next to the
# file as `coreruleset_fix.lua.bak`; never commit that.
#
# After flipping, the Kong worker must reload to pick up the change:
#   docker compose restart kong
#
# Usage:
#   ./toggle-crs-fix.sh off   # disable the fix layer (use original CRS only)
#   ./toggle-crs-fix.sh on    # restore

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FILE="${REPO_ROOT}/kong/plugins/karna/rules/coreruleset_fix.lua"
BAK="${FILE}.bak"

STUB='-- Empty stub for CRS regression benchmarking (no rule controls applied).
-- Swap with toggle-crs-fix.sh; do NOT commit this stubbed version.
local _M = {}
_M.global_fps = {}
return _M
'

case "${1:-}" in
    off)
        if [ -f "${BAK}" ]; then
            echo "Already disabled (backup exists at ${BAK})."
            exit 0
        fi
        cp "${FILE}" "${BAK}"
        printf '%s' "${STUB}" > "${FILE}"
        echo "Disabled. Backup at ${BAK}. Now: docker compose restart kong"
        ;;
    on)
        if [ ! -f "${BAK}" ]; then
            echo "Already enabled (no backup found)."
            exit 0
        fi
        mv "${BAK}" "${FILE}"
        echo "Restored. Now: docker compose restart kong"
        ;;
    *)
        echo "Usage: $0 off|on" >&2
        exit 1
        ;;
esac
