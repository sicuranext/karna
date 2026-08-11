#!/usr/bin/env bash
# Adversarial suite for `isSet` + `negated: true` ("variable is absent").
#
# Why a shell script and not hurl: this suite needs to reconfigure the plugin
# between groups (blocking on/off, redis on/off, on_error variants) and a Kong
# config PATCH takes a moment to reach every worker. hurl has no sleep, so the
# assertions would be racy.
#
# Run against the dev stack:
#   ./ka-integration-tests/001_negated_isset_bypass.sh
#   KONG_PROXY=localhost:28000 KONG_ADMIN=localhost:28001 ./...  # override
#   WITH_REDIS_OUTAGE=1 ./...   # also run group E (stops/starts karna-redis)
#
# Every case is labelled with the behaviour it pins:
#   [FEATURE]  the documented contract (docs/rules.html:223) — fails before the fix
#   [BYPASS]   an attacker trying to defeat an ACL built on negated isSet
#   [GUARD]    behaviour that must NOT change; a diff here means collateral damage
#   [KNOWN]    accepted limitation, pinned so it cannot regress silently

set -uo pipefail

PROXY="${KONG_PROXY:-localhost:28000}"
ADMIN="${KONG_ADMIN:-localhost:28001}"
UPSTREAM="${KARNA_TEST_UPSTREAM:-http://echo:8080}"
HOSTHDR="isset.local"
TOKEN="test-token-not-a-real-secret"
SETTLE="${SETTLE:-5}"

SVC=isset-bypass-svc
RT=isset-bypass-route
PLUGIN_ID=""

pass=0; fail=0; skip=0

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
note() { printf '    %s\n' "$*"; }

# assert <label> <expected> <curl args...>
assert() {
  local label="$1" want="$2"; shift 2
  local got
  got=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOSTHDR" "$@")
  if [[ "$got" == "$want" ]]; then
    printf '  \033[32mPASS\033[0m %-52s %s\n' "$label" "$got"; pass=$((pass+1))
  else
    printf '  \033[31mFAIL\033[0m %-52s got %s, want %s\n' "$label" "$got" "$want"; fail=$((fail+1))
  fi
}

# configure <json-config-fragment>
configure() {
  local cfg="$1"
  curl -s -X PATCH "http://$ADMIN/plugins/$PLUGIN_ID" \
       -H 'Content-Type: application/json' -d "{\"config\":$cfg}" -o /dev/null
  sleep "$SETTLE"
}

# rules_json <rule-object>... -> a JSON array of JSON strings for rules_request
rules_json() { python3 -c '
import json,sys
print(json.dumps([json.dumps(json.loads(a)) for a in sys.argv[1:]]))' "$@"; }

setup() {
  curl -s -X PUT "http://$ADMIN/services/$SVC" -d name=$SVC -d url="$UPSTREAM" -o /dev/null
  curl -s -X PUT "http://$ADMIN/routes/$RT" -d name=$RT \
       -d "hosts[]=$HOSTHDR" -d 'paths[]=/' -d service.name=$SVC -o /dev/null
  PLUGIN_ID=$(curl -s -X POST "http://$ADMIN/plugins" -H 'Content-Type: application/json' \
    -d "{\"name\":\"karna\",\"service\":{\"name\":\"$SVC\"},\"config\":{
          \"engine_blocking_mode\":true,\"local_rules_enabled\":true,
          \"coreruleset_enabled\":false,\"ignore_from_local_ips\":false}}" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
  [[ -n "$PLUGIN_ID" ]] || { echo "could not create plugin"; exit 1; }
  sleep "$SETTLE"
}

teardown() {
  [[ -n "$PLUGIN_ID" ]] && curl -s -X DELETE "http://$ADMIN/plugins/$PLUGIN_ID" -o /dev/null
  curl -s -X DELETE "http://$ADMIN/routes/$RT" -o /dev/null
  curl -s -X DELETE "http://$ADMIN/services/$SVC" -o /dev/null
}
trap teardown EXIT

# ---------------------------------------------------------------------------
# The ACL under test: block unless x-api-key is present AND equals TOKEN.
# 461 = absent (negated isSet), 462 = present but wrong (negated eq).
# Distinct statuses so a test can tell WHICH rule decided.
# ---------------------------------------------------------------------------
ACL_ABSENT=$(cat <<JSON
{"id":"acl_absent","phase":"access","message":"missing key","log":true,
 "conditions":[{"variables":["request.header.value:x-api-key"],"op":"isSet","negated":true}],
 "action":{"fixed_response":{"status_code":461}}}
JSON
)
ACL_WRONG=$(cat <<JSON
{"id":"acl_wrong","phase":"access","message":"wrong key","log":true,
 "conditions":[{"variables":["request.header.value:x-api-key"],"op":"eq","negated":true,"value":"$TOKEN"}],
 "action":{"fixed_response":{"status_code":462}}}
JSON
)

setup

# ===========================================================================
say "A — the documented contract (fails before the fix)"
configure "{\"engine_blocking_mode\":true,\"coreruleset_enabled\":false,
            \"rules_request\":$(rules_json "$ACL_ABSENT" "$ACL_WRONG")}"

assert "[FEATURE] A1 header absent"            461 "http://$PROXY/get"
assert "[GUARD]   A2 header present, correct"   200 -H "X-Api-Key: $TOKEN" "http://$PROXY/get"
assert "[GUARD]   A3 header present, wrong"     462 -H "X-Api-Key: nope"   "http://$PROXY/get"
assert "[GUARD]   A4 header present, empty"     462 -H "X-Api-Key;"        "http://$PROXY/get"

say "A5 — OR semantics across variables in one condition"
note "matched_conditions increments once per condition (condition_already_counted),"
note "so multiple variables are OR'd: 'at least one absent'."
A5=$(cat <<JSON
{"id":"acl_or","phase":"access","message":"either absent",
 "conditions":[{"variables":["request.header.value:x-api-key","request.header.value:x-tenant"],
                "op":"isSet","negated":true}],
 "action":{"fixed_response":{"status_code":465}}}
JSON
)
configure "{\"rules_request\":$(rules_json "$A5")}"
assert "[FEATURE] A5a both absent"              465 "http://$PROXY/get"
assert "[FEATURE] A5b only one present"         465 -H "X-Api-Key: x" "http://$PROXY/get"
assert "[GUARD]   A5c both present"             200 -H "X-Api-Key: x" -H "X-Tenant: y" "http://$PROXY/get"

# ===========================================================================
say "B — bypass: defeat the ACL by confusing header resolution"
configure "{\"rules_request\":$(rules_json "$ACL_ABSENT" "$ACL_WRONG")}"

assert "[GUARD]   B1 UPPERCASE header name"     200 -H "X-API-KEY: $TOKEN" "http://$PROXY/get"
assert "[GUARD]   B2 mixed case name"           200 -H "x-ApI-kEy: $TOKEN" "http://$PROXY/get"
note   "B3: kong.request.get_header normalises _ to -, so Karna sees X_Api_Key as"
note   "x-api-key. Broader than a strict backend, safe direction for deny rules."
assert "[KNOWN]   B3 underscore variant"        200 -H "X_Api_Key: $TOKEN" "http://$PROXY/get"
note   "B4/B5: the always-on duplicate-header gate (ka_engine.lua:6113) fires on ANY"
note   "header whose value resolves to a table, before the rule loop."
assert "[GUARD]   B4 duplicated, good+evil"     403 -H "X-Api-Key: $TOKEN" -H "X-Api-Key: evil" "http://$PROXY/get"
assert "[GUARD]   B5 duplicated, evil+good"     403 -H "X-Api-Key: evil" -H "X-Api-Key: $TOKEN" "http://$PROXY/get"
assert "[GUARD]   B6 value trailing whitespace" 200 -H "X-Api-Key: $TOKEN " "http://$PROXY/get"
assert "[BYPASS]  B7 token case-flipped"        462 -H "X-Api-Key: ${TOKEN^^}" "http://$PROXY/get"
assert "[BYPASS]  B8 token with Bearer prefix"  462 -H "X-Api-Key: Bearer $TOKEN" "http://$PROXY/get"
assert "[BYPASS]  B9 token URL-encoded"         462 -H "X-Api-Key: test%2dtoken" "http://$PROXY/get"

say "B10 — the duplicate gate is gated by engine_blocking_mode (ka_engine.lua:6182)"
note "In detection-only the gate logs but does not block, and the :<name> selector"
note "sees only the FIRST duplicate value. Pin the blind spot so it is a decision,"
note "not a surprise. Expect 200 everywhere (nothing blocks in detection-only);"
note "the assertion that matters is in the audit log, checked below."
configure "{\"engine_blocking_mode\":false}"
curl -s -o /dev/null -H "Host: $HOSTHDR" -H "X-Api-Key: first" -H "X-Api-Key: second" "http://$PROXY/get?dupmarker=1"
sleep 2
if docker exec karna-kong sh -c 'cat /usr/local/openresty/nginx/logs/karna_auditlog_*.jsonl' 2>/dev/null \
   | grep -q '"value": *"first"'; then
  printf '  \033[33mKNOWN\033[0m %-52s only first duplicate inspected\n' "[KNOWN]   B10 detection-only duplicate blind spot"
  skip=$((skip+1))
else
  printf '  \033[31mFAIL\033[0m %-52s expected first-value-only inspection\n' "[KNOWN]   B10"
  fail=$((fail+1))
fi
configure "{\"engine_blocking_mode\":true}"

say "B11 — the reserved self-identification path is not covered by any rule"
note "handler.lua short-circuits GET /.well-known/karna in access BEFORE the rule"
note "loop. It never reaches upstream, but an ACL cannot suppress it either."
assert "[KNOWN]   B11 /.well-known/karna, no key" 200 "http://$PROXY/.well-known/karna"

# ===========================================================================
say "C — bypass: negated isSet on a rule carrying rule_control"
note "THE vector the fix opens. A matching control rule applies its ctl:* side"
note "effects, so it can switch CRS detection OFF for the request. With negation"
note "the trigger is ABSENCE, i.e. the default state of ordinary traffic."
XSS='/get?q=<script>alert(1)</script>'

CTL_POS=$(cat <<'JSON'
{"id":"ctl_pos","phase":"access","message":"exclusion","action":{},
 "conditions":[{"variables":["request.header.value:x-trusted"],"op":"isSet"}],
 "rule_control":[{"remove_rule":{"rule_id":"941000-941999"}},
                 {"remove_rule":{"rule_id":"949000-949999"}}]}
JSON
)
configure "{\"coreruleset_enabled\":true,\"rules_request\":$(rules_json "$CTL_POS")}"
assert "[GUARD]   C1 XSS, no x-trusted"         403 "http://$PROXY$XSS"
note   "C2 documents today's behaviour: an operator who keys an exclusion on"
note   "attacker-controlled input has already disabled their WAF. Unchanged by the fix."
assert "[KNOWN]   C2 XSS + x-trusted (ctl fires)" 200 -H "X-Trusted: 1" "http://$PROXY$XSS"

CTL_NEG=$(cat <<'JSON'
{"id":"ctl_neg","phase":"access","message":"exclusion","action":{},
 "conditions":[{"variables":["request.header.value:x-trusted"],"op":"isSet","negated":true}],
 "rule_control":[{"remove_rule":{"rule_id":"941000-941999"}},
                 {"remove_rule":{"rule_id":"949000-949999"}}]}
JSON
)
configure "{\"coreruleset_enabled\":true,\"rules_request\":$(rules_json "$CTL_NEG")}"
note "C3 is the decision point. Policy chosen: negated isSet on a rule that carries"
note "rule_control is REJECTED at rule load with a WARN, because the failure mode is"
note "'CRS silently off for all traffic'. So CRS must still block. If the policy is"
note "changed to allow it, this expectation flips to 200 and must be documented."
assert "[BYPASS]  C3 XSS, no x-trusted, !isSet ctl" 403 "http://$PROXY$XSS"
assert "[GUARD]   C4 XSS + x-trusted, !isSet ctl"   403 -H "X-Trusted: 1" "http://$PROXY$XSS"

# ===========================================================================
say "D — no collateral: other negated operators keep ModSec parity on absence"
note "A negated condition fires only when the positive fails AND a value exists."
note "isSet is the single documented exception. These must not change."
D_RX=$(cat <<'JSON'
{"id":"d_rx","phase":"access","message":"neg rx",
 "conditions":[{"variables":["request.header.value:x-absent"],"op":"rx","negated":true,"value":"^ok$"}],
 "action":{"fixed_response":{"status_code":471}}}
JSON
)
D_EQ=$(cat <<'JSON'
{"id":"d_eq","phase":"access","message":"neg eq",
 "conditions":[{"variables":["request.header.value:x-absent"],"op":"eq","negated":true,"value":"ok"}],
 "action":{"fixed_response":{"status_code":472}}}
JSON
)
D_IP=$(cat <<'JSON'
{"id":"d_ip","phase":"access","message":"neg ipMatch",
 "conditions":[{"variables":["request.header.value:x-absent"],"op":"ipMatch","negated":true,"value":"10.0.0.0/8"}],
 "action":{"fixed_response":{"status_code":473}}}
JSON
)
D_CHAIN=$(cat <<'JSON'
{"id":"d_chain","phase":"access","message":"chain with empty cond",
 "conditions":[{"variables":["request.header.value:x-absent"],"op":"isSet"},
               {"variables":["request.arg.value"],"op":"rx","value":"anything"}],
 "action":{"fixed_response":{"status_code":474}}}
JSON
)
configure "{\"coreruleset_enabled\":false,\"rules_request\":$(rules_json "$D_RX" "$D_EQ" "$D_IP" "$D_CHAIN")}"
assert "[GUARD]   D1 !rx on absent header"      200 "http://$PROXY/get"
assert "[GUARD]   D2 !eq on absent header"      200 "http://$PROXY/get"
assert "[GUARD]   D3 !ipMatch on absent header" 200 "http://$PROXY/get"
assert "[GUARD]   D4 chain, cond1 empty"        200 "http://$PROXY/get?q=anything"

say "D5 — a rule control that empties the target is NOT 'variable absent'"
note "ctl:ruleRemoveTargetById deletes keys from values (ka_engine.lua:3180-3229)."
note "Target excluded must keep skipping the condition, not fire negated isSet."
D_CTL=$(cat <<'JSON'
{"id":"d_ctl_src","phase":"access","message":"drop target","action":{},
 "conditions":[{"variables":["request.raw_path"],"op":"rx","value":"/get"}],
 "rule_control":[{"remove_target_from_rule_by_id":{"rule_id":"d_ctl_tgt","target":"x-api-key"}}]}
JSON
)
D_CTL_T=$(cat <<'JSON'
{"id":"d_ctl_tgt","phase":"access","message":"absent after ctl",
 "conditions":[{"variables":["request.header.value:x-api-key"],"op":"isSet","negated":true}],
 "action":{"fixed_response":{"status_code":475}}}
JSON
)
configure "{\"rules_request\":$(rules_json "$D_CTL" "$D_CTL_T")}"
assert "[GUARD]   D5 target removed by ctl"     200 -H "X-Api-Key: $TOKEN" "http://$PROXY/get"

# ===========================================================================
say "E — Redis: three states, not two (present / absent / unknown)"
note "ka_engine.lua:3136 folds a Redis error into {} unless on_error=fail_closed."
note "With negation that inverts the configured intent, so 'unknown' must be its"
note "own state. An allowlist rule must not turn a Redis outage into a total outage."
# Fixed key, no %{remote_addr} macro: this group tests the three-state logic,
# not client-IP resolution, and the Kong-visible peer IP inside Docker is not
# worth guessing from the test side.
E_RULE=$(cat <<'JSON'
{"id":"e_allow","phase":"access","message":"not in allowlist",
 "conditions":[{"variables":["redis.allow:testclient"],"op":"isSet","negated":true}],
 "action":{"fixed_response":{"status_code":481}}}
JSON
)
configure "{\"redis_inspect_enabled\":true,\"redis_on_error\":\"skip\",
            \"redis_host\":\"${REDIS_HOST:-redis}\",\"redis_port\":${REDIS_PORT:-6379},
            \"rules_request\":$(rules_json "$E_RULE")}"

if docker exec karna-redis redis-cli ping >/dev/null 2>&1; then
  docker exec karna-redis redis-cli del "allow:testclient" >/dev/null 2>&1
  assert "[FEATURE] E1 key absent, redis up"     481 "http://$PROXY/get"
  docker exec karna-redis redis-cli set "allow:testclient" 1 >/dev/null 2>&1
  assert "[FEATURE] E2 key present, redis up"    200 "http://$PROXY/get"

  if [[ "${WITH_REDIS_OUTAGE:-0}" == "1" ]]; then
    docker stop karna-redis >/dev/null
    configure '{"redis_on_error":"skip"}'
    assert "[BYPASS]  E3 redis down, on_error=skip"        200 "http://$PROXY/get"
    configure '{"redis_on_error":"fail_open"}'
    assert "[BYPASS]  E4 redis down, on_error=fail_open"   200 "http://$PROXY/get"
    configure '{"redis_on_error":"fail_closed"}'
    assert "[FEATURE] E5 redis down, on_error=fail_closed" 481 "http://$PROXY/get"
    docker start karna-redis >/dev/null; sleep 3
  else
    note "E3-E5 skipped (set WITH_REDIS_OUTAGE=1 to stop/start karna-redis)"; skip=$((skip+3))
  fi

  configure '{"redis_inspect_enabled":false,"redis_on_error":"skip"}'
  note "Feature switched off resolves the variable to nil, which is not 'absent'."
  assert "[GUARD]   E6 redis_inspect_enabled=false" 200 "http://$PROXY/get"
else
  note "redis unreachable, group E skipped"; skip=$((skip+6))
fi

# ===========================================================================
say "F — unresolvable variables: no validation, by decision"
note "Karna does not validate variable names anywhere, and we are not adding a"
note "partial validator for this one operator. An unresolvable variable therefore"
note "reads as absent and a negated isSet on it fires on every request. That fails"
note "closed and loud (100% block at deploy, one service, a rule just written), so"
note "it is left as operator error. Both cases below are pinned as behaviour, not"
note "as something to protect against."
F_RESP=$(cat <<'JSON'
{"id":"f_resp","phase":"access","message":"response var in access phase",
 "conditions":[{"variables":["response.status"],"op":"isSet","negated":true}],
 "action":{"fixed_response":{"status_code":491}}}
JSON
)
F_TYPO=$(cat <<'JSON'
{"id":"f_typo","phase":"access","message":"typo in variable name",
 "conditions":[{"variables":["request.heder.value:x-api-key"],"op":"isSet","negated":true}],
 "action":{"fixed_response":{"status_code":492}}}
JSON
)
configure "{\"redis_inspect_enabled\":false,\"rules_request\":$(rules_json "$F_RESP")}"
note "A response.* variable resolves to nothing in the access phase"
note "(ka_engine.lua:2865), so it reads as absent and the rule fires."
assert "[KNOWN]   F1 !isSet on response.status"  491 "http://$PROXY/get"

configure "{\"rules_request\":$(rules_json "$F_TYPO")}"
note "Same for a typo'd name: no branch of the dispatch claims it, so it reads as"
note "absent. Blocks everything. Operator error, visible on the first request."
assert "[KNOWN]   F2 !isSet on typo'd variable"  492 "http://$PROXY/get"

# ===========================================================================
say "G — count: parity and its limits"
G_OK=$(cat <<'JSON'
{"id":"g_ok","phase":"access","message":"count on supported var",
 "conditions":[{"variables":["count:request.header.value:x-api-key"],"op":"eq","value":"0"}],
 "action":{"fixed_response":{"status_code":495}}}
JSON
)
G_NUM=$(cat <<'JSON'
{"id":"g_num","phase":"access","message":"count compared to a JSON number",
 "conditions":[{"variables":["count:request.header.value:x-api-key"],"op":"eq","value":0}],
 "action":{"fixed_response":{"status_code":496}}}
JSON
)
G_UNSUP=$(cat <<'JSON'
{"id":"g_unsup","phase":"access","message":"count on unsupported var",
 "conditions":[{"variables":["count:request.remote_addr"],"op":"eq","value":"0"}],
 "action":{"fixed_response":{"status_code":497}}}
JSON
)
configure "{\"rules_request\":$(rules_json "$G_OK")}"
assert "[GUARD]   G1 count eq \"0\", header absent"  495 "http://$PROXY/get"
assert "[GUARD]   G2 count eq \"0\", header present" 200 -H "X-Api-Key: x" "http://$PROXY/get"

configure "{\"rules_request\":$(rules_json "$G_NUM")}"
note "__match_op_eq is a string compare, so a JSON number never matches the"
note "stringified count. Silent dead rule; pinned so nobody rediscovers it."
assert "[KNOWN]   G3 count eq 0 (JSON number)"       200 "http://$PROXY/get"

configure "{\"rules_request\":$(rules_json "$G_UNSUP")}"
note "The count: resolver whitelists inner variables (ka_engine.lua:2637). Anything"
note "outside it yields count 0, so the rule fires on every request."
assert "[KNOWN]   G4 count on unsupported variable"  497 -H "X-Api-Key: x" "http://$PROXY/get"

# ===========================================================================
printf '\n\033[1mresult\033[0m  pass=%d fail=%d skipped=%d\n' "$pass" "$fail" "$skip"
[[ "$fail" -eq 0 ]] || exit 1
