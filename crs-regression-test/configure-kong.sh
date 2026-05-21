#!/usr/bin/env bash
# Idempotent Kong setup for the CRS regression suite.
#
# Creates (or updates) a service `echo` pointing at the upstream echo
# container, a route on Host: karna-test, and a karna plugin instance
# tuned for the regression runner:
#   - engine_blocking_mode=true   (must be true; runner expects 403 with body)
#   - private_debug=true          (causes Karna to emit the matched rule
#                                  object as JSON body so the runner can
#                                  find `"id":"<rule_id>"`)
#   - coreruleset_enabled=true
#   - auditlog_enabled=false      (suite runs are quiet; flip back when
#                                  diagnosing a specific failure)
#
# Usage:
#   ./configure-kong.sh                  # default: localhost:28001
#   ADMIN=http://kong-other:8001 ./configure-kong.sh

set -euo pipefail

ADMIN="${ADMIN:-http://localhost:28001}"
PARANOIA="${PARANOIA:-1}"

echo "Waiting for Kong Admin API at ${ADMIN} ..."
until curl -fs "${ADMIN}/" >/dev/null 2>&1; do
    sleep 2
done
echo "Kong is up."

upsert_service() {
    if curl -fs "${ADMIN}/services/echo" >/dev/null 2>&1; then
        curl -fs -X PATCH "${ADMIN}/services/echo" \
            -d "url=http://echo:8080" >/dev/null
        echo "service: updated"
    else
        curl -fs -X POST "${ADMIN}/services" \
            -d "name=echo" \
            -d "url=http://echo:8080" >/dev/null
        echo "service: created"
    fi
}

upsert_route() {
    # The CRS regression runner forces Host: integration.local for tests
    # that carry a Host header in the YAML (most of them) and falls back
    # to Host: karna-test otherwise. Accept both.
    local route_id
    route_id=$(curl -fs "${ADMIN}/services/echo/routes" | python3 -c "import sys,json; d=json.load(sys.stdin); print(next((r['id'] for r in d.get('data',[]) if r.get('name')=='karna-test-route'),''))")

    local payload=(
        -d "name=karna-test-route"
        -d "hosts[]=karna-test"
        -d "hosts[]=integration.local"
        -d "paths[]=/"
        -d "strip_path=false"
    )

    if [ -n "${route_id}" ]; then
        # Replace the hosts list deterministically: DELETE + POST is simpler
        # than juggling array merges via PATCH against Kong's admin API.
        curl -fs -X DELETE "${ADMIN}/routes/${route_id}" >/dev/null
        curl -fs -X POST "${ADMIN}/services/echo/routes" "${payload[@]}" >/dev/null
        echo "route: replaced (${route_id} → new)"
    else
        curl -fs -X POST "${ADMIN}/services/echo/routes" "${payload[@]}" >/dev/null
        echo "route: created"
    fi
}

upsert_plugin() {
    local plugin_id
    plugin_id=$(curl -fs "${ADMIN}/services/echo/plugins" \
        | python3 -c "import sys,json; d=json.load(sys.stdin); print(next((p['id'] for p in d.get('data',[]) if p['name']=='karna'),''))")

    local payload=(
        -d "name=karna"
        -d "config.engine_blocking_mode=true"
        -d "config.private_debug=true"
        -d "config.coreruleset_enabled=true"
        -d "config.local_rules_enabled=false"
        -d "config.paranoia_level=${PARANOIA}"
        -d "config.auditlog_enabled=false"
        -d "config.ignore_from_local_ips=false"
    )

    if [ -n "${plugin_id}" ]; then
        curl -fs -X PATCH "${ADMIN}/plugins/${plugin_id}" "${payload[@]}" >/dev/null
        echo "plugin: updated (${plugin_id})"
    else
        curl -fs -X POST "${ADMIN}/services/echo/plugins" "${payload[@]}" >/dev/null
        echo "plugin: created"
    fi
}

# Add Kong's built-in request-termination plugin AFTER karna in the access
# phase. Karna has PRIORITY 8300, request-termination has PRIORITY 2 — so
# Karna runs first. If Karna matches, it kong.response.exit()s with the rule
# object (in private_debug mode) and request-termination never runs. If
# Karna doesn't match, request-termination short-circuits with a 200 empty
# body — no upstream traffic at all. This shaves ~30-60ms per request that
# would otherwise round-trip to the echo container. Essential for full-suite
# runs (4600+ tests).
upsert_termination() {
    local plugin_id
    plugin_id=$(curl -fs "${ADMIN}/services/echo/plugins" \
        | python3 -c "import sys,json; d=json.load(sys.stdin); print(next((p['id'] for p in d.get('data',[]) if p['name']=='request-termination'),''))")

    local payload=(
        -d "name=request-termination"
        -d "config.status_code=200"
        -d "config.message=ok"
    )

    if [ -n "${plugin_id}" ]; then
        curl -fs -X PATCH "${ADMIN}/plugins/${plugin_id}" "${payload[@]}" >/dev/null
        echo "request-termination: updated (${plugin_id})"
    else
        curl -fs -X POST "${ADMIN}/services/echo/plugins" "${payload[@]}" >/dev/null
        echo "request-termination: created"
    fi
}

upsert_service
upsert_route
upsert_plugin
upsert_termination

echo
echo "Configured. Smoke-test with:"
echo "  curl -s -H 'Host: karna-test' -H 'X-Karna-Test: true' \\"
echo "    'http://localhost:28000/?q=cat%20/etc/passwd' | head -c 200"
