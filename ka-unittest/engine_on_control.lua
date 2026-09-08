-- ka-unittest/engine_on_control.lua
--
-- Guards the `engine_on` rule control (ModSecurity `ctl:ruleEngine=On`): a
-- rule that matches forces terminal actions for the REST of the request, even
-- when the service runs `engine_blocking_mode = false` or an earlier control
-- applied `detection_only`. This is how a virtual patch blocks on a service
-- that is otherwise only observing.
--
-- Load-bearing properties pinned here:
--   1. the SecLang parser emits `{engine_on = true}` for `ctl:ruleEngine=On`,
--      also when the ctl sits on the LAST link of a chain (the ModSecurity
--      idiom: it fires only when the whole chain matched), with `Off` winning
--      over `On` and DetectionOnly/On resolved by declaration order;
--   2. the applier keeps `engine_on` and `detection_only` mutually exclusive
--      (last applied wins), never lets `engine_on` survive next to `engine_off`,
--      records the forcing rule id, and is strict about `== true`;
--   3. `rule_blocking_enabled` honours `engine_on` before the service setting;
--   4. the dispatch order in handler.lua:evaluate_rules — the rule's own
--      controls are applied BEFORE its own action is decided, so `engine_on`
--      + `fixed_response` blocks on a detection service, and the per-entry
--      `blocked` flag is recorded at that moment;
--   5. the audit log tells the operator why a detection-only service answered
--      403: v2 `engine.mode = "blocking"` + `engine.forced_by_rule`, per-match
--      `action` decided per entry (an earlier detect stays `detect`); v1 gets a
--      `karna/engine-forced-on/<id>` tag on the message.
--
-- (1) and (5) run against the REAL seclang.lua / ka_utils.lua behind stubs, so
-- they cannot drift from the source. (2)-(4) are replicated inline (same
-- convention as rule_control_runtime.lua / log_only_action.lua) because the
-- engine and the handler need kong globals at load. KEEP IN SYNC with:
--   kong/plugins/karna/modules/ka_engine.lua  __apply_rule_controls_inline
--   kong/plugins/karna/handler.lua            rule_blocking_enabled,
--                                             evaluate_rules (controls-first block,
--                                             match_entry.blocked)
--
-- Fixtures are synthetic: example.com, x-upstream-* headers, 9999xx rule ids.
--
-- Run from repo root:
--   lua    ka-unittest/engine_on_control.lua
--   luajit ka-unittest/engine_on_control.lua

package.path = "./kong/plugins/karna/modules/?.lua;" .. package.path
package.preload["inspect"] = function() return function() return "" end end

local fails = 0
local function ok(cond, name)
    if cond then print("  ok  - " .. name)
    else print("  FAIL- " .. name); fails = fails + 1 end
end

local function find(tbl, pred)
    for _, v in ipairs(tbl or {}) do if pred(v) then return v end end
    return nil
end
local function has_control(controls, key)
    return find(controls, function(c) return c[key] == true end) ~= nil
end
local function count(t) local n = 0; for _ in pairs(t) do n = n + 1 end; return n end
local function keyset(t)
    local ks = {}
    for k in pairs(t) do ks[#ks + 1] = tostring(k) end
    table.sort(ks)
    return table.concat(ks, ",")
end

-- ============================================================
print("- SecLang: ctl:ruleEngine=On")
-- ============================================================
local seclang = require("seclang")

local c = seclang.__get_rule_controls("id:999901,phase:2,deny,status:403,ctl:ruleEngine=On")
ok(has_control(c, "engine_on"), "ctl:ruleEngine=On → engine_on")
ok(not has_control(c, "detection_only") and not has_control(c, "engine_off"),
   "…and nothing else")
ok(#c == 1, "exactly one control")

c = seclang.__get_rule_controls("id:999902,phase:1,pass,ctl:ruleEngine=On,ctl:ruleRemoveById=942100")
ok(has_control(c, "engine_on"), "On in the middle of the action list (followed by a comma)")
ok(find(c, function(x) return x.remove_rule and x.remove_rule.rule_id == "942100" end) ~= nil,
   "the generic ctl: pass still sees the other directive")

c = seclang.__get_rule_controls("id:999903,phase:1,pass,ctl:ruleEngine=Off,ctl:ruleEngine=On")
ok(has_control(c, "engine_off") and not has_control(c, "engine_on"),
   "Off wins over On (same rule, either order)")
c = seclang.__get_rule_controls("id:999903,phase:1,pass,ctl:ruleEngine=On,ctl:ruleEngine=Off")
ok(has_control(c, "engine_off") and not has_control(c, "engine_on"),
   "Off wins over On (On written first)")

c = seclang.__get_rule_controls("id:999904,phase:1,pass,ctl:ruleEngine=DetectionOnly,ctl:ruleEngine=On")
ok(has_control(c, "engine_on") and not has_control(c, "detection_only"),
   "DetectionOnly then On → On (last written wins)")
c = seclang.__get_rule_controls("id:999904,phase:1,pass,ctl:ruleEngine=On,ctl:ruleEngine=DetectionOnly")
ok(has_control(c, "detection_only") and not has_control(c, "engine_on"),
   "On then DetectionOnly → DetectionOnly (last written wins)")

c = seclang.__get_rule_controls("id:999905,phase:1,pass,ctl:ruleEngine=Once")
ok(not has_control(c, "engine_on"), "`On` must be the whole value: ctl:ruleEngine=Once emits nothing")

c = seclang.__get_rule_controls("id:999906,phase:1,pass,ctl:ruleEngine=DetectionOnly")
ok(has_control(c, "detection_only") and #c == 1, "DetectionOnly alone still parses as before")

print("- SecLang: the ModSecurity chain idiom — ctl on the last link")
local parsed = seclang.parse_isolated([[
SecRule REQUEST_URI "@beginsWith /api/legacy/export" \
    "id:999907,phase:2,deny,status:403,log,msg:'virtual patch: legacy export RCE',\
    tag:'karna-test',chain"
    SecRule ARGS:cmd "@contains ;" "t:none,ctl:ruleEngine=On"
]])
local r = parsed["999907"]
ok(r ~= nil, "chain parsed under the head id")
ok(r and #r.conditions == 2, "two links → two conditions (one rule, full match required)")
ok(r and r.action and r.action.fixed_response and r.action.fixed_response.status_code == 403,
   "deny,status:403 on the head → fixed_response 403")
ok(r and has_control(r.rule_control, "engine_on"),
   "ctl:ruleEngine=On on the LAST link lands on the head rule's rule_control")
ok(r and #r.rule_control == 1, "…exactly once (no double registration)")

parsed = seclang.parse_isolated([[
SecRule REQUEST_HEADERS:x-upstream-tenant "@streq acme" \
    "id:999908,phase:1,pass,nolog,chain"
    SecRule REQUEST_URI "@beginsWith /api/" "ctl:ruleRemoveById=920420"
]])
r = parsed["999908"]
ok(r and find(r.rule_control, function(x) return x.remove_rule and x.remove_rule.rule_id == "920420" end) ~= nil,
   "any ctl:* on a chain link reaches the head (ruleRemoveById too)")

-- ============================================================
print("")
print("- applier + rule_blocking_enabled (inline copies)")
-- ============================================================
-- SUT — the per-request store, as handler.lua:access initialises it
local function new_store()
    return {
        ids = {}, ids_targets = {}, tags = {}, removed_tags = {},
        remove_target_from_all_rules = {},
        engine_off = false, detection_only = false, engine_on = false,
        body_access_off = false, audit_request_body = false,
    }
end

-- SUT — copy of ka_engine.lua:__apply_rule_controls_inline, the engine-state
-- directives only (the removal directives are covered by rule_control_runtime.lua)
local function apply_rule_controls(rc, controls, rule_id)
    if not controls or not rc then return end
    for _, control in pairs(controls) do
        if control.detection_only then
            rc.detection_only = true
            rc.engine_on = false
            rc.engine_forced_by = nil
        end
        if control.engine_on == true then
            rc.engine_on = true
            rc.detection_only = false
            if rule_id ~= nil then rc.engine_forced_by = tostring(rule_id) end
        end
        if control.body_access_off then rc.body_access_off = true end
        if control.audit_request_body == true then rc.audit_request_body = true end
        if control.engine_off then rc.engine_off = true end
    end
    if rc.engine_off and rc.engine_on then
        rc.engine_on = false
        rc.engine_forced_by = nil
    end
end

-- SUT — copy from handler.lua
local function detection_only_active(rc) return (rc and rc.detection_only) == true end
local function rule_blocking_enabled(rc, engine_blocking_mode)
    if rc and rc.engine_on == true then return true end
    if not engine_blocking_mode then return false end
    return not detection_only_active(rc)
end

local rc = new_store()
ok(not rule_blocking_enabled(rc, false), "detection service, no control → not blocking")
apply_rule_controls(rc, { { engine_on = true } }, "999901")
ok(rc.engine_on == true, "applier set engine_on")
ok(rc.engine_forced_by == "999901", "…and recorded the forcing rule id")
ok(rule_blocking_enabled(rc, false), "detection service + engine_on → blocking")
ok(rule_blocking_enabled(rc, true), "blocking service + engine_on → still blocking")

rc = new_store()
apply_rule_controls(rc, { { engine_on = true } }, 999902)
ok(rc.engine_forced_by == "999902", "numeric rule id is stored as a string")

print("- DetectionOnly and On are one switch: last applied wins")
rc = new_store()
apply_rule_controls(rc, { { detection_only = true } }, "999903")
ok(not rule_blocking_enabled(rc, true), "blocking service + DetectionOnly → suppressed")
apply_rule_controls(rc, { { engine_on = true } }, "999904")
ok(rc.detection_only == false, "engine_on cleared detection_only")
ok(rule_blocking_enabled(rc, false) and rule_blocking_enabled(rc, true),
   "…and blocking is back, on either kind of service")
apply_rule_controls(rc, { { detection_only = true } }, "999905")
ok(rc.engine_on == false and rc.engine_forced_by == nil,
   "a later detection_only clears engine_on and the forcing id")
ok(not rule_blocking_enabled(rc, true), "…so the request is observe-only again")

print("- Off is stronger than On, whatever the order")
rc = new_store()
apply_rule_controls(rc, { { engine_off = true }, { engine_on = true } }, "999906")
ok(rc.engine_off == true and rc.engine_on == false and rc.engine_forced_by == nil,
   "same list, Off first → engine_on dropped")
rc = new_store()
apply_rule_controls(rc, { { engine_on = true }, { engine_off = true } }, "999906")
ok(rc.engine_off == true and rc.engine_on == false, "same list, On first → engine_on dropped")
rc = new_store()
apply_rule_controls(rc, { { engine_on = true } }, "999907")
apply_rule_controls(rc, { { engine_off = true } }, "999908")
ok(rc.engine_on == false and rc.engine_forced_by == nil, "a later Off clears an earlier On")
rc = new_store()
apply_rule_controls(rc, { { engine_off = true } }, "999908")
apply_rule_controls(rc, { { engine_on = true } }, "999907")
ok(rc.engine_on == false, "an On after Off does not stick (the loops have stopped anyway)")

print("- strictness")
rc = new_store()
apply_rule_controls(rc, { { engine_on = "yes" } }, "999909")
ok(rc.engine_on == false and rc.engine_forced_by == nil,
   "engine_on = \"yes\" does NOT flip (strict == true; a stray string cannot turn a detection service into blocking)")
apply_rule_controls(rc, { { engine_on = 1 } }, "999909")
ok(rc.engine_on == false, "engine_on = 1 does NOT flip either")
rc = new_store()
apply_rule_controls(rc, { { engine_on = true } }, nil)
ok(rc.engine_on == true and rc.engine_forced_by == nil,
   "no rule id → forced but unattributed (forced_by absent, not \"nil\")")
rc = new_store()
apply_rule_controls(rc, { { engine_on = true } }, "999910")
ok(rc.detection_only == false and rc.body_access_off == false and rc.audit_request_body == false
   and count(rc.ids) == 0, "engine_on touches nothing else in the store")

-- ============================================================
print("")
print("- evaluate_rules dispatch order (inline copy): own controls first, then own action")
-- ============================================================
-- SUT — the shape of handler.lua:evaluate_rules after a terminal match. Returns
-- the match entry and what happened to the request.
local function dispatch(rc, plugin_blocking, rule)
    local entry = { rule = rule, sanitized = false }
    if rule.rule_control then
        apply_rule_controls(rc, rule.rule_control, rule.id)
    end
    if rule.action and rule.action.fix_matched_parts then
        if not detection_only_active(rc) then entry.sanitized = true end
        return entry, "upstream"
    end
    local blocking = rule_blocking_enabled(rc, plugin_blocking)
    if rule.action and rule.action.fixed_response then
        entry.blocked = blocking
    end
    if blocking and rule.action and rule.action.fixed_response then
        return entry, "exit " .. tostring(rule.action.fixed_response.status_code or 403)
    end
    return entry, "upstream"
end
-- SUT — the loop entry guard (loop_rules / loop_rule_controls_pass)
local function loop_runs(rc) return not (rc and rc.engine_off) end

local BLOCK = { fixed_response = { status_code = 403, body = "Forbidden\r\n" } }
local patch = { id = "999901", phase = "access", log = true, message = "virtual patch",
                tags = { "karna-test" }, action = BLOCK, rule_control = { { engine_on = true } } }
local plain = { id = "999902", phase = "access", log = true, message = "plain block",
                tags = { "karna-test" }, action = BLOCK }

local entry, outcome = dispatch(new_store(), false, patch)
ok(outcome == "exit 403", "detection service: engine_on + fixed_response → 403")
ok(entry.blocked == true, "…entry recorded as blocked")

entry, outcome = dispatch(new_store(), false, plain)
ok(outcome == "upstream", "detection service: same rule without engine_on → flows upstream")
ok(entry.blocked == false, "…entry recorded as not blocked (audit label `detect`)")

rc = new_store()
apply_rule_controls(rc, { { detection_only = true } }, "999903")   -- an earlier exclusion rule
entry, outcome = dispatch(rc, false, patch)
ok(outcome == "exit 403", "detection_only applied earlier, then the engine_on rule → 403")
ok(rc.engine_forced_by == "999901", "forced by the patch rule")

rc = new_store()
apply_rule_controls(rc, { { engine_off = true } }, "999905")
ok(not loop_runs(rc), "engine_off applied earlier → the rule loop does not run, nothing is evaluated")

-- ModSecurity order consequence: a rule that declares both deny and
-- ctl:ruleEngine=DetectionOnly observes rather than blocks, on a blocking service.
local contradictory = { id = "999904", action = BLOCK, rule_control = { { detection_only = true } } }
entry, outcome = dispatch(new_store(), true, contradictory)
ok(outcome == "upstream" and entry.blocked == false,
   "blocking service: detection_only + fixed_response on ONE rule → observe (controls applied before the action)")

print("- fix_matched_parts under the two states")
local fixer = { id = "999906", action = { fix_matched_parts = { remove_chars_pattern = "[<>]" } } }
rc = new_store(); apply_rule_controls(rc, { { detection_only = true } }, "999903")
entry = dispatch(rc, true, fixer)
ok(entry.sanitized == false, "detection_only → sanitising suppressed")
apply_rule_controls(rc, { { engine_on = true } }, "999901")
entry = dispatch(rc, true, fixer)
ok(entry.sanitized == true, "engine_on afterwards → sanitising enforced again")

-- ============================================================
print("")
print("- audit log (real ka_utils behind stubs)")
-- ============================================================
local CJSON = { empty_array = coroutine.create(function() end) }
package.preload["cjson"] = function() return CJSON end
package.preload["kong.plugins.karna.version"] = function()
    return { version = "0.0.0-test", commit = "deadbee", commit_short = "deadbee", built_at = "test" }
end
_G.ngx = {
    re = { match = function() return nil end },
    now = function() return 1700000000.5 end,
    time = function() return 1700000000 end,
    var = { request_id = "req-0001", remote_addr = "203.0.113.7", remote_port = "51234",
            server_addr = "10.0.0.1", server_port = "8000", server_id = "srv-1",
            request_time = "0.030", upstream_response_time = "0.020", bytes_sent = "312" },
    log = function() end,
    worker = { id = function() return 0 end },
    encode_base64 = function(s) return s end,
}
_G.kong = {
    log = { debug = function() end, warn = function() end, err = function() end, notice = function() end },
    ctx = { shared = {}, plugin = {} },
    router = {
        get_service = function() return { id = "svc-1", name = "acme_www.example.com" } end,
        get_route   = function() return { id = "route-1" } end,
    },
    request = {
        get_header          = function() return nil end,
        get_headers         = function() return { host = "www.example.com", ["x-upstream-marker"] = "t1" } end,
        get_path_with_query = function() return "/api/legacy/export?cmd=id%3Bls" end,
        get_method          = function() return "GET" end,
        get_http_version    = function() return 1.1 end,
    },
    response = {
        get_status  = function() return 403 end,
        get_headers = function() return { ["content-type"] = "text/plain" } end,
    },
    service = { response = {
        get_status  = function() return 200 end,
        get_headers = function() return {} end,
    } },
}
local utils = dofile("./kong/plugins/karna/modules/ka_utils.lua")

local PARTS = { { matched_on = "request.arg.value:cmd", matched_value = "id;ls" } }
local DETECTION_SVC = { engine_blocking_mode = false, paranoia_level = 1 }
local BLOCKING_SVC  = { engine_blocking_mode = true,  paranoia_level = 1 }

-- a request on a detection service: rule 999902 matched first and only detected,
-- then 999901 forced the engine On and blocked; a gate-style entry without the
-- per-entry flag rides along
kong.ctx.plugin = { rule_controls = { engine_on = true, detection_only = false, engine_forced_by = "999901" } }
local matched = {
    { rule = plain, part = PARTS, sanitized = false, blocked = false },
    { rule = patch, part = PARTS, sanitized = false, blocked = true },
    { rule = { id = "999950", action = BLOCK, tags = { "karna-test" } }, part = PARTS, sanitized = false },
}
local v2 = utils:get_auditlog_v2(matched, DETECTION_SVC)
ok(v2.engine.mode == "blocking", "v2: engine.mode reads blocking on a detection service")
ok(v2.engine.forced_by_rule == "999901", "v2: engine.forced_by_rule names the rule")
ok(v2.matches[1].action == "detect", "v2: the earlier match stays `detect` (per-entry decision)")
ok(v2.matches[2].action == "block", "v2: the forcing rule's match reads `block`")
ok(v2.matches[3].action == "detect",
   "v2: an entry without the per-entry flag falls back to the service setting (detect)")

kong.ctx.plugin = { rule_controls = { engine_on = false, detection_only = false } }
v2 = utils:get_auditlog_v2({ { rule = plain, part = PARTS, sanitized = false, blocked = false } }, DETECTION_SVC)
ok(v2.engine.mode == "detection", "v2: without the control a detection service reads detection")
ok(v2.engine.forced_by_rule == nil, "v2: forced_by_rule absent when nothing forced")
ok(keyset(v2.engine) == "commit,mode,name,paranoia_level,version",
   "v2: engine block unchanged for services that never use the control")
ok(v2.matches[1].action == "detect", "v2: detect label unchanged")

v2 = utils:get_auditlog_v2({ { rule = plain, part = PARTS, sanitized = false } }, BLOCKING_SVC)
ok(v2.engine.mode == "blocking" and v2.matches[1].action == "block",
   "v2: blocking service, legacy entry → blocking / block (unchanged)")
kong.ctx.plugin = { rule_controls = { engine_on = false, detection_only = true } }
v2 = utils:get_auditlog_v2({ { rule = plain, part = PARTS, sanitized = false, blocked = false } }, BLOCKING_SVC)
ok(v2.engine.mode == "detection" and v2.matches[1].action == "detect",
   "v2: blocking service + DetectionOnly → detection / detect (unchanged)")

print("- v1 marker")
kong.ctx.plugin = { rule_controls = { engine_on = true, detection_only = false, engine_forced_by = "999901" } }
local before = #patch.tags
local v1 = utils:get_auditlog(patch, PARTS)
local tags = v1.transaction.messages[1].details.tags
ok(find(tags, function(t) return t == "karna/engine-forced-on/999901" end) ~= nil,
   "v1: the message carries the karna/engine-forced-on/<id> tag")
ok(find(tags, function(t) return t == "karna-test" end) ~= nil, "v1: the rule's own tags are kept")
ok(#patch.tags == before and tags ~= patch.tags,
   "v1: the cached rule's tags table is NOT mutated (fresh array)")
ok(v1.transaction.messages[1].details.ruleId == "999901", "v1: ruleId untouched")

-- the forcer can be a control-only pass rule; the blocking rule is then another one
kong.ctx.plugin = { rule_controls = { engine_on = true, detection_only = false, engine_forced_by = "999903" } }
v1 = utils:get_auditlog(plain, PARTS)
ok(find(v1.transaction.messages[1].details.tags, function(t) return t == "karna/engine-forced-on/999903" end) ~= nil,
   "v1: the tag names the FORCING rule, not the matched one")

kong.ctx.plugin = { rule_controls = { engine_on = false, detection_only = false } }
v1 = utils:get_auditlog(plain, PARTS)
ok(v1.transaction.messages[1].details.tags == plain.tags,
   "v1: without the control the message carries the rule's tags table itself (byte-identical document)")

print(string.format("\n%d test(s) failed", fails))
os.exit(fails == 0 and 0 or 1)
