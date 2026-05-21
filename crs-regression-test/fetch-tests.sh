#!/usr/bin/env bash
# Fetch the official OWASP CoreRuleSet regression test YAMLs into ./tests/.
#
# The version must match the CRS version baked into docker/kong/Dockerfile
# (CRS_VERSION arg). At the time of writing that's 4.26.0. Override with the
# CRS_VERSION env var.
#
# Usage:
#   ./fetch-tests.sh                     # fetch default CRS version
#   CRS_VERSION=4.27.0 ./fetch-tests.sh  # fetch a specific version

set -euo pipefail

CRS_VERSION="${CRS_VERSION:-4.26.0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST_DIR="${SCRIPT_DIR}/tests"

echo "Fetching OWASP CRS v${CRS_VERSION} regression tests into ${DEST_DIR}"

mkdir -p "${DEST_DIR}"
rm -rf "${DEST_DIR}"/*

TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

curl -fsSL "https://github.com/coreruleset/coreruleset/archive/refs/tags/v${CRS_VERSION}.tar.gz" \
    | tar -xz -C "${TMPDIR}"

SRC="${TMPDIR}/coreruleset-${CRS_VERSION}/tests/regression/tests"
if [ ! -d "${SRC}" ]; then
    echo "ERROR: regression test directory not found at ${SRC}" >&2
    echo "(layout may have changed in this CRS version)" >&2
    exit 1
fi

cp -R "${SRC}"/* "${DEST_DIR}/"

count=$(find "${DEST_DIR}" -name "*.yaml" -o -name "*.yml" | wc -l | tr -d ' ')
echo "Fetched ${count} regression test files."
echo
echo "Next:"
echo "  1. docker compose up --build     # bring the dev stack up"
echo "  2. Configure a Kong service + Karna plugin instance (see README.md)"
echo "  3. python3 start.py --testfile tests/   # run the whole suite"
