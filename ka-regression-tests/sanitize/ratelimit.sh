#!/usr/bin/env bash
#
# Rate-limit action regression test.
#
# Stands up an isolated service / route / Karna plugin with CRS off
# and a local rule whose action is `rate_limit` (limit=3, window=5s).
# Verifies:
#   - the first `limit` requests pass (200 from request-termination)
#   - the (limit + 1)th request is blocked with 429
#   - response carries the Retry-After header
#   - after `window_seconds` the counter expires and traffic flows again
#
# CRS off because pre-existing rules can occasionally fire on plain
# paths and would race with the assertion. The mechanism under test —
# Redis-backed counter, threshold check, 429 dispatch — is fully
# covered by a deterministic local rule.

set -euo pipefail

ADMIN="${ADMIN:-http://localhost:28001}"
PROXY="${PROXY:-http://localhost:28000}"
HOST="ratelimit.local"
SERVICE="echo-ratelimit"
ROUTE="echo-ratelimit-route"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
blue()  { printf '\033[34m%s\033[0m\n' "$*"; }

fail=0
assert_eq() {
    local got="$1" want="$2" label="$3"
    if [ "$got" = "$want" ]; then
        green "  PASS  $label"
    else
        red "  FAIL  $label"
        red "    got:  $got"
        red "    want: $want"
        fail=1
    fi
}
assert_contains() {
    local got="$1" needle="$2" label="$3"
    if echo "$got" | grep -qF "$needle"; then
        green "  PASS  $label"
    else
        red "  FAIL  $label"
        red "    body fragment did not contain: $needle"
        red "    got: $(echo "$got" | head -c 200)"
        fail=1
    fi
}

blue "==> waiting for Kong Admin API at $ADMIN"
for i in $(seq 1 60); do
    if curl -fs "$ADMIN/status" >/dev/null 2>&1; then break; fi
    sleep 1
done

blue "==> upsert service $SERVICE"
if curl -fs "$ADMIN/services/$SERVICE" >/dev/null 2>&1; then
    curl -fs -X PATCH "$ADMIN/services/$SERVICE" -d "url=http://echo:8080" >/dev/null
else
    curl -fs -X POST "$ADMIN/services" -d "name=$SERVICE" -d "url=http://echo:8080" >/dev/null
fi

blue "==> upsert route $ROUTE"
route_id=$(curl -fs "$ADMIN/services/$SERVICE/routes" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(next((r['id'] for r in d.get('data',[]) if r.get('name')=='$ROUTE'),''))")
if [ -n "$route_id" ]; then
    curl -fs -X DELETE "$ADMIN/routes/$route_id" >/dev/null
fi
curl -fs -X POST "$ADMIN/services/$SERVICE/routes" \
    -d "name=$ROUTE" \
    -d "hosts[]=$HOST" \
    -d "paths[]=/" \
    -d "strip_path=false" >/dev/null

# Local rule: every request on `/limited` increments a Redis counter
# keyed by remote_addr. limit=3, window=5s.
RL_RULE='{
  "id":"local_ratelimit_test",
  "phase":"access",
  "log":true,
  "message":"rate-limit-test",
  "tags":["ratelimit","test"],
  "conditions":[{"op":"beginsWith","transform":[],"value":"/limited","variables":["request.raw_path"]}],
  "action":{"rate_limit":{"key":"%{remote_addr}","limit":3,"window_seconds":5}}
}'

blue "==> upsert karna plugin (CRS off, rate-limit rule injected)"
plugin_id=$(curl -fs "$ADMIN/services/$SERVICE/plugins" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(next((p['id'] for p in d.get('data',[]) if p['name']=='karna'),''))")

payload=(
    -d "name=karna"
    -d "config.engine_blocking_mode=true"
    -d "config.coreruleset_enabled=false"
    -d "config.local_rules_enabled=true"
    -d "config.ignore_from_local_ips=false"
    -d "config.auditlog_enabled=false"
    -d "config.redis_host=redis"
    -d "config.redis_port=6379"
    -d "config.check_special_chars_in_path=false"
    -d "config.check_invalid_chars_in_path=false"
    -d "config.total_arg_value_length=10000000"
    -d "config.limit_arg_value_length=1000000"
    -d "config.limit_arg_name_length=10000"
    -d "config.limit_arg_num=10000"
    --data-urlencode "config.rules_request[]=${RL_RULE}"
)
if [ -n "$plugin_id" ]; then
    curl -fs -X PATCH "$ADMIN/plugins/$plugin_id" "${payload[@]}" >/dev/null
else
    curl -fs -X POST "$ADMIN/services/$SERVICE/plugins" "${payload[@]}" >/dev/null
fi

# Settle + warmup. The counter we'll target lives at
# karna:rl:local_ratelimit_test:<client_ip>. Wiping it now keeps
# repeated runs idempotent.
sleep 3
docker exec karna-redis redis-cli --no-auth-warning KEYS 'karna:rl:local_ratelimit_test:*' \
    | xargs -r docker exec karna-redis redis-cli --no-auth-warning DEL >/dev/null 2>&1 || true
for _ in $(seq 1 20); do
    curl -fs -o /dev/null -H "Host: $HOST" "$PROXY/" || true
done
# clear the warmup-side counter increments from the warm path (none —
# warmup hits `/` which doesn't match `/limited` — but be safe).
docker exec karna-redis redis-cli --no-auth-warning KEYS 'karna:rl:local_ratelimit_test:*' \
    | xargs -r docker exec karna-redis redis-cli --no-auth-warning DEL >/dev/null 2>&1 || true

# -------- tests --------

blue "==> tests 1-3: requests under the limit pass with 200"
for i in 1 2 3; do
    status=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST" "$PROXY/limited?n=$i")
    assert_eq "$status" "200" "request $i / 3 → 200 (under limit)"
done

blue "==> test 4: request (limit + 1) blocked with 429"
http_body=$(mktemp)
status=$(curl -s -o "$http_body" -w "%{http_code}" -H "Host: $HOST" "$PROXY/limited?n=4")
assert_eq "$status" "429" "4th request → 429"
assert_contains "$(cat "$http_body")" "Too Many Requests" "429 body carries default message"

blue "==> test 5: Retry-After header set automatically"
got_header=$(curl -s -D - -o /dev/null -H "Host: $HOST" "$PROXY/limited?n=5" | grep -i '^Retry-After:' | tr -d '\r' || true)
assert_contains "$got_header" "Retry-After: 5" "Retry-After header matches window_seconds"

blue "==> test 6: counter expires after window — traffic flows again"
# Wait `window + 1`. Redis TTL is fixed-window (set on counter
# creation), so we wait the full window plus a beat.
sleep 6
status=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST" "$PROXY/limited?n=6")
assert_eq "$status" "200" "request after window expiry → 200"

blue "==> test 7: non-matching path is never rate-limited"
# Counter is now fresh again (post-expiry). Hit `/other` 10 times in
# a row — it doesn't match the rule's beginsWith, so the counter
# should never increment.
for i in 1 2 3 4 5 6 7 8 9 10; do
    status=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST" "$PROXY/other?n=$i")
    if [ "$status" != "200" ]; then
        red "  FAIL  unrelated path got $status on request $i"
        fail=1
        break
    fi
done
[ "$fail" -eq 0 ] && green "  PASS  10 requests on /other all 200 (no rate-limit leakage)"

rm -f "$http_body"

if [ "$fail" -ne 0 ]; then
    red "RATE-LIMIT REGRESSION FAILED"
    exit 1
fi
green "RATE-LIMIT REGRESSION PASSED"
