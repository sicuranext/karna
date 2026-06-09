#!/usr/bin/env bash
# Fetch the official OWASP CoreRuleSet regression test YAMLs into ./tests/.
#
# By default fetches the full suite and then prunes test YAMLs that target
# rules tagged `paranoia-level/N` with N > CRS_MAX_PL. Karna ships and is
# benched at PL1 (production posture); PL2/3/4 rules generate too many false
# positives for real-world deployments and aren't part of the supported
# operational surface. Tests targeting them are not signal — leaving them in
# the suite inflates the "fail" count with rules we wouldn't load in prod
# anyway. The filter is `CRS_MAX_PL=0` to disable (= keep everything).
#
# The version must match the CRS version baked into docker/kong/Dockerfile
# (CRS_VERSION arg). At the time of writing that's 4.26.0.
#
# Usage:
#   ./fetch-tests.sh                       # default: CRS 4.26.0, only PL1 tests
#   CRS_MAX_PL=2 ./fetch-tests.sh          # keep PL1+PL2 tests
#   CRS_MAX_PL=0 ./fetch-tests.sh          # keep everything (no filter)
#   CRS_VERSION=4.27.0 ./fetch-tests.sh    # different CRS version

set -euo pipefail

CRS_VERSION="${CRS_VERSION:-4.26.0}"
# sha256 of the v4.26.0 source tarball. If you bump CRS_VERSION, set CRS_SHA256
# to the new tarball's hash (the assert below fails closed on a mismatch).
CRS_SHA256="${CRS_SHA256:-d923e991e671d2665cd73758b8dc3df6c3b0a9df96d798e98f088d5a81a76dc0}"
CRS_MAX_PL="${CRS_MAX_PL:-1}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST_DIR="${SCRIPT_DIR}/tests"

echo "Fetching OWASP CRS v${CRS_VERSION} regression tests into ${DEST_DIR}"

mkdir -p "${DEST_DIR}"
rm -rf "${DEST_DIR}"/*

TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

curl -fsSL "https://github.com/coreruleset/coreruleset/archive/refs/tags/v${CRS_VERSION}.tar.gz" \
    -o "${TMPDIR}/crs.tar.gz"
echo "${CRS_SHA256}  ${TMPDIR}/crs.tar.gz" | shasum -a 256 -c -
tar -xz -C "${TMPDIR}" -f "${TMPDIR}/crs.tar.gz"

CRS_ROOT="${TMPDIR}/coreruleset-${CRS_VERSION}"
SRC="${CRS_ROOT}/tests/regression/tests"
if [ ! -d "${SRC}" ]; then
    echo "ERROR: regression test directory not found at ${SRC}" >&2
    echo "(layout may have changed in this CRS version)" >&2
    exit 1
fi

cp -R "${SRC}"/* "${DEST_DIR}/"

count=$(find "${DEST_DIR}" -name "*.yaml" -o -name "*.yml" | wc -l | tr -d ' ')
echo "Fetched ${count} regression test files."

if [ "${CRS_MAX_PL}" -gt 0 ] 2>/dev/null; then
    echo "Pruning tests targeting rules with paranoia-level > ${CRS_MAX_PL} ..."
    python3 - "${CRS_ROOT}/rules" "${DEST_DIR}" "${CRS_MAX_PL}" <<'PY'
import os, re, sys

rules_dir, tests_dir, max_pl = sys.argv[1], sys.argv[2], int(sys.argv[3])

# Build rule_id -> max paranoia level (default 1 if rule is tagged anywhere)
rule_pl = {}
id_re = re.compile(r"id:(\d+)")
pl_re = re.compile(r"paranoia-level/(\d+)")
for fname in os.listdir(rules_dir):
    if not fname.endswith(".conf"): continue
    cur = None
    for line in open(os.path.join(rules_dir, fname), errors="ignore"):
        m = id_re.search(line)
        if m:
            cur = m.group(1)
            rule_pl.setdefault(cur, 1)
        m = pl_re.search(line)
        if m and cur:
            pl = int(m.group(1))
            if pl > rule_pl[cur]: rule_pl[cur] = pl

# Remove YAML files for rules above the max
removed = 0
kept = 0
for dp, _, files in os.walk(tests_dir):
    for f in files:
        if not (f.endswith(".yaml") or f.endswith(".yml")): continue
        rid = f.split(".")[0]
        pl = rule_pl.get(rid, 1)
        if pl > max_pl:
            os.remove(os.path.join(dp, f))
            removed += 1
        else:
            kept += 1

# Prune empty category directories
for dp, dirs, files in os.walk(tests_dir, topdown=False):
    if not dirs and not files:
        try: os.rmdir(dp)
        except OSError: pass

print(f"  kept {kept} YAML files (PL<={max_pl}), removed {removed} (PL>{max_pl}).")
PY
else
    echo "CRS_MAX_PL=0 → keeping all paranoia levels (no filter)."
fi

count=$(find "${DEST_DIR}" -name "*.yaml" -o -name "*.yml" | wc -l | tr -d ' ')
echo "Final test file count: ${count}"
echo
echo "Next:"
echo "  1. docker compose up --build     # bring the dev stack up"
echo "  2. Configure a Kong service + Karna plugin instance (see README.md)"
echo "  3. python3 start.py --testfile tests/   # run the suite"
