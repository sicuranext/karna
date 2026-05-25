#!/usr/bin/env bash
#
# Config-level rule_action_overrides / rule_response_overrides
# regression test.
#
# Exercises the two override mechanisms end-to-end against a running
# Karna stack with three deterministic local JSON rules — `coreruleset`
# is OFF on this service so the test never races with CRS rules
# (which carry their own pre-existing flakiness on the dev image,
# e.g. 920171 occasionally firing spuriously).
#
# Local rules under test:
#   - xss_block:   tag=attack-xss,  action=block  → covered by action override (→ fix)
#   - sqli_block:  tag=attack-sqli, action=block  → covered by response override (→ 451)
#   - lfi_block:   tag=attack-lfi,  action=block  → outside both override scopes
#
# Each rule fires on a deterministic payload, so the assertions are
# stable regardless of which worker handles the request.

set -euo pipefail

ADMIN="${ADMIN:-http://localhost:28001}"
PROXY="${PROXY:-http://localhost:28000}"
HOST="overrides.local"
SERVICE="echo-overrides"
ROUTE="echo-overrides-route"

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

# Three deterministic detection rules — each blocks on a specific
# shape and carries a distinct tag so the overrides can target it
# precisely.
XSS_RULE='{
  "id":"local_xss_block","phase":"access","log":true,
  "message":"xss-shape","tags":["attack-xss"],
  "conditions":[{"op":"rx","transform":[],"value":"[<>\"'"'"'&]","variables":["request.arg.value:name"]}],
  "action":{"fixed_response":{"status_code":403,"body":"Forbidden\r\n","headers":{"content-type":"text/plain"}}}
}'

SQLI_RULE='{
  "id":"local_sqli_block","phase":"access","log":true,
  "message":"sqli-shape","tags":["attack-sqli"],
  "conditions":[{"op":"rx","transform":[],"value":"(?i)union|select|--","variables":["request.arg.value:foo"]}],
  "action":{"fixed_response":{"status_code":403,"body":"Forbidden\r\n","headers":{"content-type":"text/plain"}}}
}'

LFI_RULE='{
  "id":"local_lfi_block","phase":"access","log":true,
  "message":"lfi-shape","tags":["attack-lfi"],
  "conditions":[{"op":"rx","transform":[],"value":"\\.\\./","variables":["request.arg.value:file"]}],
  "action":{"fixed_response":{"status_code":403,"body":"Forbidden\r\n","headers":{"content-type":"text/plain"}}}
}'

# Override 1: every rule tagged `attack-xss` → sanitize instead of block.
ACTION_OVERRIDE_XSS='{
  "selector": { "tags": ["attack-xss"] },
  "action":   { "type": "fix", "remove_chars_pattern": "[<>\"'"'"'&]" }
}'

# Override 2: every rule tagged `attack-sqli` → 451 + custom body +
# x-blocked-by header. Exercises the response override path which only
# fires when the (post-action-override) effective action is still a
# block.
RESPONSE_OVERRIDE_SQLI='{
  "selector": { "tags": ["attack-sqli"] },
  "response": { "status_code": 451,
                "body": "Refused for legal reasons.",
                "headers": { "x-blocked-by": "karna-overrides" } }
}'

blue "==> upsert karna plugin (CRS off, 3 local rules + both overrides)"
plugin_id=$(curl -fs "$ADMIN/services/$SERVICE/plugins" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(next((p['id'] for p in d.get('data',[]) if p['name']=='karna'),''))")

payload=(
    -d "name=karna"
    -d "config.engine_blocking_mode=true"
    -d "config.coreruleset_enabled=false"
    -d "config.local_rules_enabled=true"
    -d "config.ignore_from_local_ips=false"
    -d "config.auditlog_enabled=false"
    -d "config.check_special_chars_in_path=false"
    -d "config.check_invalid_chars_in_path=false"
    -d "config.total_arg_value_length=10000000"
    -d "config.limit_arg_value_length=1000000"
    -d "config.limit_arg_name_length=10000"
    -d "config.limit_arg_num=10000"
    --data-urlencode "config.rules_request[]=${XSS_RULE}"
    --data-urlencode "config.rules_request[]=${SQLI_RULE}"
    --data-urlencode "config.rules_request[]=${LFI_RULE}"
    --data-urlencode "config.rule_action_overrides[]=${ACTION_OVERRIDE_XSS}"
    --data-urlencode "config.rule_response_overrides[]=${RESPONSE_OVERRIDE_SQLI}"
)
if [ -n "$plugin_id" ]; then
    curl -fs -X PATCH "$ADMIN/plugins/$plugin_id" "${payload[@]}" >/dev/null
else
    curl -fs -X POST "$ADMIN/services/$SERVICE/plugins" "${payload[@]}" >/dev/null
fi

# Settling time + per-worker cache warmup. The override cache is
# keyed on `tostring(plugin_conf)` and warms lazily on first request;
# without warmup the first real test can hit a cold worker.
sleep 3
for _ in $(seq 1 20); do
    curl -fs -o /dev/null -H "Host: $HOST" "$PROXY/?warmup=1" || true
done

# -------- tests --------

blue "==> test 1: local_xss_block — action override switches block to fix"
got=$(curl -fs -H "Host: $HOST" "$PROXY/?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('query',{}).get('name',''))")
assert_eq "$got" "scriptalert(1)/script" "xss-shape payload sanitized; upstream sees stripped name"

blue "==> test 2: O'Brien-style apostrophe gets stripped"
got=$(curl -fs -H "Host: $HOST" "$PROXY/?name=O%27Brien" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('query',{}).get('name',''))")
assert_eq "$got" "OBrien" "apostrophe stripped; upstream sees OBrien"

blue "==> test 3: local_sqli_block — response override yields 451 + custom body"
http_body=$(mktemp)
http_status=$(curl -s -o "$http_body" -w "%{http_code}" \
    -H "Host: $HOST" \
    "$PROXY/?foo=UNION%20SELECT")
assert_eq "$http_status" "451" "sqli-shape → status_code override 451"
assert_contains "$(cat "$http_body")" "Refused for legal reasons." "sqli-shape → custom body present"

blue "==> test 4: x-blocked-by header set by response override"
got_header=$(curl -s -D - -o /dev/null \
    -H "Host: $HOST" \
    "$PROXY/?foo=UNION%20SELECT" | grep -i '^x-blocked-by:' | tr -d '\r' || true)
assert_contains "$got_header" "karna-overrides" "sqli-shape → x-blocked-by header injected"

blue "==> test 5: local_lfi_block — outside override scope, default 403"
http_status_lfi=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Host: $HOST" \
    "$PROXY/?file=../../etc/passwd")
assert_eq "$http_status_lfi" "403" "lfi-shape (out of override scope) → default 403"

rm -f "$http_body"

if [ "$fail" -ne 0 ]; then
    red "OVERRIDES REGRESSION FAILED"
    exit 1
fi
green "OVERRIDES REGRESSION PASSED"
