#!/usr/bin/env sh
# Build the Karna production Docker image with the build identity stamped in:
# version + git commit + build date are baked into kong/plugins/karna/version.lua
# (the prod stage of docker/Dockerfile rewrites it from the build ARGs). The
# running plugin then reports them on /.well-known/karna and in the audit log.
#
#   ./scripts/build.sh            # build via docker compose (docker-compose.prod.yml)
#   ./scripts/build.sh image      # plain `docker build` -> karna:latest
#
# `.git` is excluded from the Docker build context, so the commit can't be read
# inside the build — it must be passed in. This wrapper does that for you.
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

KARNA_COMMIT="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
KARNA_BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
export KARNA_COMMIT KARNA_BUILD_DATE

echo "Building Karna @ ${KARNA_COMMIT} (${KARNA_BUILD_DATE})"

if [ "${1:-}" = "image" ]; then
  docker build -f "$ROOT/docker/Dockerfile" --target prod \
    --build-arg KARNA_COMMIT="$KARNA_COMMIT" \
    --build-arg KARNA_BUILD_DATE="$KARNA_BUILD_DATE" \
    -t karna:latest "$ROOT"
else
  # docker compose reads KARNA_COMMIT / KARNA_BUILD_DATE from the environment
  # (referenced as build args in docker-compose.prod.yml).
  docker compose -f "$ROOT/docker/docker-compose.prod.yml" build
fi
