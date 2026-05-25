#!/usr/bin/env bash
#
# Sanitize-not-block regression test — verifies that a rule carrying a
# `fix_matched_parts` action strips dangerous characters from matched
# targets in place and forwards the (sanitized) request upstream
# instead of returning a 403. This is Karna's killer feature for
# false-positive reduction: a payload that looks like SQLi/XSS but is
# really a proper name or a street address goes through.
#
# Stands up an isolated service / route / plugin instance with
# `coreruleset_enabled=false` so no CRS rule races with the test's
# own local rule. Runs against the docker-compose dev stack that the
# CRS regression workflow already brings up.
#
# Usage:
#   ./run.sh                      # default ADMIN=http://localhost:28001
#   ADMIN=http://kong:8001 ./run.sh

set -euo pipefail

ADMIN="${ADMIN:-http://localhost:28001}"
PROXY="${PROXY:-http://localhost:28000}"
HOST="sanitize.local"
SERVICE="echo-sanitize"
ROUTE="echo-sanitize-route"

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

blue "==> waiting for Kong Admin API at $ADMIN"
for i in $(seq 1 60); do
    if curl -fs "$ADMIN/status" >/dev/null 2>&1; then break; fi
    sleep 1
done

# ---------- setup: service + route ----------
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

# ---------- setup: Karna plugin with a sanitize rule ----------
# The rule matches any apostrophe / angle-bracket / quote / ampersand /
# semicolon in `?name=…` and strips them via fix_matched_parts. CRS pack
# is OFF so nothing else can race with this rule.
SANITIZE_RULE='{
  "id":"sanitize_test_001",
  "phase":"access",
  "log":true,
  "message":"sanitize-xss-name",
  "tags":["sanitize","test"],
  "conditions":[{
    "op":"rx",
    "transform":[],
    "value":"[<>\"'"'"';&]",
    "variables":["request.arg.value:name"]
  }],
  "action":{
    "fix_matched_parts":{"remove_chars_pattern":"[<>\"'"'"';&]"}
  }
}'

blue "==> upsert karna plugin (coreruleset_enabled=false, local rule injected)"
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
    --data-urlencode "config.rules_request[]=${SANITIZE_RULE}"
)
if [ -n "$plugin_id" ]; then
    curl -fs -X PATCH "$ADMIN/plugins/$plugin_id" "${payload[@]}" >/dev/null
else
    curl -fs -X POST "$ADMIN/services/$SERVICE/plugins" "${payload[@]}" >/dev/null
fi

# Probe loop for route propagation. CI runners can take ~10s to
# propagate a brand-new service / route across all Kong workers; on
# the local dev image it's ~1s. Bail out early once the route
# answers, then warm the per-worker rule cache so the first real
# test doesn't lose a request to a cold worker.
blue "==> waiting for route propagation"
for i in $(seq 1 60); do
    s=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST" "$PROXY/")
    if [ "$s" = "200" ]; then green "    route active after ${i}s"; break; fi
    sleep 1
    if [ "$i" -eq 60 ]; then red "    route never became active (last: $s)"; exit 1; fi
done
for _ in $(seq 1 20); do
    curl -fs -o /dev/null -H "Host: $HOST" "$PROXY/get?warmup=1" || true
done

# ---------- tests ----------
#
# Each test sends a query and reads what the echo upstream actually saw
# in the `?name=…` parameter. The echo container reflects every request
# as JSON including a `query` block, so we can assert directly on what
# Karna handed off upstream.
#
# Reliability: every payload triggers the rule (the regex matches), so
# the sanitize path runs deterministically — none of the
# pre-existing CRS flakiness applies here.

blue "==> test 1: O'Brien — apostrophe stripped, upstream sees OBrien"
got=$(curl -fs -H "Host: $HOST" "$PROXY/get?name=O%27Brien" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('query',{}).get('name',''))")
assert_eq "$got" "OBrien" "name=O'Brien → upstream sees OBrien"

blue "==> test 2: <script>alert(1)</script> — angle-brackets + quotes stripped"
got=$(curl -fs -H "Host: $HOST" "$PROXY/get?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('query',{}).get('name',''))")
assert_eq "$got" "scriptalert(1)/script" "name=<script>… → upstream sees scriptalert(1)/script"

blue "==> test 3: Via dell'Orso, 5 — Italian address survives"
got=$(curl -fs -H "Host: $HOST" "$PROXY/get?name=Via%20dell%27Orso%2C%205" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('query',{}).get('name',''))")
assert_eq "$got" "Via dellOrso, 5" "name=Via dell'Orso, 5 → upstream sees Via dellOrso, 5"

blue "==> test 4: benign Mario — no match, passes through verbatim"
got=$(curl -fs -H "Host: $HOST" "$PROXY/get?name=Mario" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('query',{}).get('name',''))")
assert_eq "$got" "Mario" "name=Mario → upstream sees Mario (unmodified)"

blue "==> test 5: sanitize ignores other query keys"
got_name=$(curl -fs -H "Host: $HOST" "$PROXY/get?name=O%27Brien&other=don%27t%20touch" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('query',{}).get('name',''))")
got_other=$(curl -fs -H "Host: $HOST" "$PROXY/get?name=O%27Brien&other=don%27t%20touch" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('query',{}).get('other',''))")
assert_eq "$got_name"  "OBrien"        "matched key sanitized"
assert_eq "$got_other" "don't touch"   "unmatched key untouched"

blue "==> test 6: blocking-mode is bypassed when sanitize fires (no 403)"
status=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST" "$PROXY/get?name=O%27Brien")
assert_eq "$status" "200" "engine_blocking_mode=true + fix_matched_parts → 200, not 403"

if [ "$fail" -ne 0 ]; then
    red "SANITIZE REGRESSION FAILED"
    exit 1
fi
green "SANITIZE REGRESSION PASSED"
