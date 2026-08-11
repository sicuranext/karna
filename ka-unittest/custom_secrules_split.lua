-- ka-unittest/custom_secrules_split.lua
--
-- Inline `custom_secrules` (and the CRS exclusion-plugin .conf files) used to be
-- handed to ONE evaluator: the multi-match controls path, which deliberately
-- ignores `fixed_response`. A hand-written `SecRule ... "deny"` was therefore
-- parsed, evaluated on every request, matched — and had its terminal action
-- silently discarded. The rules are now split by the same rule the global rules
-- pack uses, and the detection half goes to the standard action dispatch.
--
-- Three pieces of logic, each with a way to go wrong:
--
--   1. is_control_only() — decides the bucket. Canonical copy is
--      `ka_compile.is_control_only`; `ka_global_rules` carries a duplicate
--      because it must stay requirable without ka_compile (its engine/compile
--      refs are injected via init() so it can be unit-tested in plain Lua). The
--      two MUST agree, and this truth table is the shared contract. Replicated
--      inline here, the same convention op_negation_normalization.lua uses:
--      neither ka_compile nor seclang loads under the Lua 5.4 CI runs.
--
--   2. The bucketing itself — right bucket, right phase, and a rule whose phase
--      this channel never evaluates must be dropped rather than parked where it
--      would silently never run.
--
--   3. __get_log() — whether a match earns an audit-log entry. The CRS loader
--      sets `rule.log` on everything it loads; rules arriving through
--      parse_isolated never went through it, so they blocked without leaving a
--      trace. Reads ModSec's nolog / auditlog / noauditlog off the action list.
--
-- Run from repo root:
--   lua ka-unittest/custom_secrules_split.lua

local fails = 0
local function ok(cond, name)
    if cond then
        print("  ok   - " .. name)
    else
        fails = fails + 1
        print("  FAIL - " .. name)
    end
end

-- ------------------------------------------------- 1. is_control_only
-- mirrors ka_compile.is_control_only / the duplicate in ka_global_rules
local function is_control_only(rule)
    if type(rule.rule_control) ~= "table" then return false end
    local action = rule.action
    if action == nil then return true end
    if type(action) ~= "table" then return false end
    return next(action) == nil
end

print("\nis_control_only — an exclusion is rule_control with no action")
ok(is_control_only({ rule_control = { {} } })                    == true,
   "rule_control, action absent")
ok(is_control_only({ rule_control = { {} }, action = {} })       == true,
   "rule_control, action empty table")
ok(is_control_only({ rule_control = {}, action = {} })           == true,
   "empty rule_control list still counts as a control rule")

print("\nis_control_only — anything carrying a real action is detection")
ok(is_control_only({ action = { fixed_response = { status_code = 403 } } }) == false,
   "action, no rule_control")
ok(is_control_only({ rule_control = { {} },
                     action = { fixed_response = { status_code = 403 } } }) == false,
   "rule_control NEXT TO an action stays detection")
-- This is the case the split exists to protect: the controls path runs no action
-- side effects, so a rule with setvar / set_log_fields / redis_incr_key next to
-- its rule_control would lose them if it were filed as a control.
ok(is_control_only({ rule_control = { {} },
                     action = { set_variable = { name = "x" } } }) == false,
   "rule_control next to a side-effect action stays detection")
ok(is_control_only({})                                           == false,
   "no rule_control at all")
ok(is_control_only({ rule_control = "notatable" })               == false,
   "rule_control of the wrong type")
ok(is_control_only({ rule_control = { {} }, action = "deny" })   == false,
   "action of the wrong type is not an empty action")

-- ------------------------------------------------- 2. bucketing
-- mirrors the split loop in handler.get_plugin_dynamic_rules
local function split(parsed)
    local out = {
        controls  = { access = {}, header_filter = {} },
        detection = { access = {}, header_filter = {} },
    }
    local dropped = 0
    for _, rule in ipairs(parsed) do
        local bucket = is_control_only(rule) and out.controls or out.detection
        local phase_list = bucket[rule.phase]
        if phase_list then
            phase_list[#phase_list + 1] = rule
        else
            dropped = dropped + 1
        end
    end
    return out, dropped
end

local BLOCK_A = { id = "1", phase = "access",        action = { fixed_response = {} } }
local BLOCK_H = { id = "2", phase = "header_filter", action = { fixed_response = {} } }
local EXCL_A  = { id = "3", phase = "access",        rule_control = { {} } }
local EXCL_H  = { id = "4", phase = "header_filter", rule_control = { {} } }
local BODY    = { id = "5", phase = "body_filter",   action = { fixed_response = {} } }
local TYPO    = { id = "6", phase = "acess",         action = { fixed_response = {} } }

print("\nbucketing — each rule lands in one bucket and one phase")
local s, dropped = split({ BLOCK_A, BLOCK_H, EXCL_A, EXCL_H })
ok(#s.detection.access == 1 and s.detection.access[1].id == "1", "block/access → detection.access")
ok(#s.detection.header_filter == 1 and s.detection.header_filter[1].id == "2",
   "block/header_filter → detection.header_filter")
ok(#s.controls.access == 1 and s.controls.access[1].id == "3", "excl/access → controls.access")
ok(#s.controls.header_filter == 1 and s.controls.header_filter[1].id == "4",
   "excl/header_filter → controls.header_filter")
ok(dropped == 0, "nothing dropped")

print("\nbucketing — a phase this channel never evaluates is dropped, not parked")
s, dropped = split({ BODY, TYPO })
ok(dropped == 2, "body_filter and a typo'd phase both dropped")
ok(#s.detection.access == 0 and #s.detection.header_filter == 0, "neither leaked into a phase")

print("\nbucketing — author order is preserved within a bucket")
local r1 = { id = "10", phase = "access", action = { fixed_response = {} } }
local r2 = { id = "11", phase = "access", action = { fixed_response = {} } }
local r3 = { id = "12", phase = "access", action = { fixed_response = {} } }
s = split({ r1, r2, r3 })
ok(s.detection.access[1].id == "10" and s.detection.access[2].id == "11"
   and s.detection.access[3].id == "12",
   "first-match-wins sees the rules in the order they were written")

print("\nbucketing — an empty input yields empty lists, not nil")
s, dropped = split({})
ok(#s.controls.access == 0 and #s.detection.access == 0
   and #s.controls.header_filter == 0 and #s.detection.header_filter == 0,
   "all four lists present and empty")
ok(dropped == 0, "nothing dropped")

-- ------------------------------------------------- 3. __get_log
-- mirrors seclang.__get_log
local function get_log(actions)
    local padded = "," .. (actions or "") .. ","
    local function has(flag)
        return string.find(padded, "," .. flag .. ",", 1, true) ~= nil
    end
    if has("noauditlog") then return false end
    if has("auditlog") then return true end
    if has("nolog") then return false end
    return true
end

print("\n__get_log — ModSec logging flags")
ok(get_log("id:1,phase:1,block")                  == true,  "default is on")
ok(get_log("id:1,nolog")                          == false, "nolog disables")
ok(get_log("id:1,auditlog")                       == true,  "auditlog enables")
ok(get_log("id:1,nolog,auditlog")                 == true,  "nolog,auditlog → on (the CRS idiom)")
ok(get_log("id:1,auditlog,nolog")                 == true,  "order does not matter")
ok(get_log("id:1,noauditlog")                     == false, "noauditlog disables")
ok(get_log("id:1,noauditlog,auditlog")            == false, "noauditlog wins, it is checked first")
ok(get_log(nil)                                   == true,  "nil actions → default on")
ok(get_log("")                                    == true,  "empty actions → default on")

print("\n__get_log — a flag at either end of the list is still a flag")
ok(get_log("nolog,id:1")                          == false, "first position")
ok(get_log("id:1,nolog")                          == false, "last position")
ok(get_log("nolog")                               == false, "only element")

print("\n__get_log — free text must not be read as a flag")
-- The actions string carries msg:'…' and logdata:'…'. Comma-delimited matching
-- is what keeps their contents out of the decision.
ok(get_log("id:1,msg:'nolog is not set here'")    == true,  "nolog inside msg")
ok(get_log("id:1,msg:'see auditlog docs',nolog")  == false, "auditlog inside msg does not enable")
ok(get_log("id:1,logdata:'nologistics'")          == true,  "flag as a substring of a word")
ok(get_log("id:1,tag:'auditlog-related'")         == true,  "auditlog as a prefix inside a tag")
-- Honest limit: a msg that itself contains a comma-delimited flag does fool it.
-- Pinned so the boundary is a known property rather than a surprise.
ok(get_log("id:1,msg:'a,nolog,b'")                == false, "known limit: ,flag, inside msg does match")

print(string.format("\n%d test(s) failed", fails))
os.exit(fails == 0 and 0 or 1)
