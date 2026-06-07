#!/usr/bin/env sh
# Package the Karna Claude Code skill into a tarball for hosting on the
# website, so a user can install it into their own agent in one line:
#
#   curl -fsSL https://karna.sicuranext.com/skill/karna-skill.tar.gz \
#     | tar -xz -C ~/.claude/skills/
#
# The tarball extracts to `karna/SKILL.md` + `karna/reference/*.md`.
# Run from anywhere; output defaults to dist/karna-skill.tar.gz (gitignored).
#
# After building, deploy alongside docs/skill/index.html:
#   aws s3 cp dist/karna-skill.tar.gz s3://karna.sicuranext.com/skill/karna-skill.tar.gz
#   aws s3 cp docs/skill/index.html  s3://karna.sicuranext.com/skill/index.html \
#       --content-type "text/html; charset=utf-8"
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/dist/karna-skill.tar.gz}"
mkdir -p "$(dirname "$OUT")"
tar -czf "$OUT" -C "$ROOT/.claude/skills" karna
echo "Wrote $OUT"
tar -tzf "$OUT"
