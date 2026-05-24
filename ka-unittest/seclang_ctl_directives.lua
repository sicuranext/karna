-- ka-unittest/seclang_ctl_directives.lua
--
-- Verify the seclang parser correctly extracts `ctl:*` directives from
-- a SecRule's actions string. Used by CRS exclusion plugins
-- (wordpress-rule-exclusions, drupal-rule-exclusions, …) to whitelist
-- per-endpoint targets without modifying the global ruleset.
--
-- Run from repo root:
--   lua ka-unittest/seclang_ctl_directives.lua

package.path = "./kong/plugins/karna/modules/?.lua;" .. package.path

-- seclang.lua does `require "inspect"` at the top for development
-- debug prints; it isn't used by the ctl parser. Provide an inline
-- stub so the unit test can run without the rockspec dep installed.
package.preload["inspect"] = function() return function() return "" end end

local seclang = require("seclang")

local fails = 0
local function ok(cond, name)
    if cond then
        print("  ok  - " .. name)
    else
        print("  FAIL- " .. name)
        fails = fails + 1
    end
end

local function deep_find(tbl, predicate)
    for _, v in ipairs(tbl) do
        if predicate(v) then return v end
    end
    return nil
end

-- Real-world example from wp-rule-exclusions-plugin (CRS upstream).
-- We exercise the four supported directives plus a couple of edge cases.
local cases = {
    {
        name = "ruleEngine=Off",
        actions = "id:9507100,phase:1,pass,t:none,nolog,ctl:ruleEngine=Off",
        check = function(controls)
            ok(#controls >= 1, "at least one control")
            local c = deep_find(controls, function(x) return x.engine_off == true end)
            ok(c ~= nil, "engine_off=true emitted")
        end,
    },
    {
        name = "ruleRemoveById single id",
        actions = "id:9507101,phase:1,pass,nolog,ctl:ruleRemoveById=920273",
        check = function(controls)
            local c = deep_find(controls, function(x)
                return x.remove_rule and x.remove_rule.rule_id == "920273"
            end)
            ok(c ~= nil, "remove_rule.rule_id=920273")
        end,
    },
    {
        name = "ruleRemoveById range",
        actions = "id:9507102,phase:1,pass,nolog,ctl:ruleRemoveById=920100-920199",
        check = function(controls)
            local c = deep_find(controls, function(x)
                return x.remove_rule and x.remove_rule.rule_id == "920100-920199"
            end)
            ok(c ~= nil, "remove_rule.rule_id range kept verbatim")
        end,
    },
    {
        name = "ruleRemoveTargetById with ARGS target",
        actions = "id:9507103,phase:1,pass,nolog,ctl:ruleRemoveTargetById=920273;ARGS:user_login",
        check = function(controls)
            local c = deep_find(controls, function(x)
                return x.remove_target_from_rule_by_id
                    and x.remove_target_from_rule_by_id.rule_id == "920273"
                    and x.remove_target_from_rule_by_id.target == "request.arg.value:user_login"
            end)
            ok(c ~= nil, "remove_target_from_rule_by_id with mapped target")
        end,
    },
    {
        name = "ruleRemoveTargetByTag with REQUEST_HEADERS lowercased",
        actions = "id:9507104,phase:1,pass,nolog,ctl:ruleRemoveTargetByTag=OWASP_CRS;REQUEST_HEADERS:Referer",
        check = function(controls)
            local c = deep_find(controls, function(x)
                return x.remove_target_rule_by_tag
                    and x.remove_target_rule_by_tag.tag == "OWASP_CRS"
                    and x.remove_target_rule_by_tag.name == "request.header.value:referer"
            end)
            ok(c ~= nil, "remove_target_rule_by_tag with lowercased header")
        end,
    },
    {
        name = "multiple ctl directives in same actions string",
        actions = "id:9507105,phase:1,pass,nolog,"
            .. "ctl:ruleRemoveTargetById=920273;ARGS:user_login,"
            .. "ctl:ruleRemoveTargetById=920280;REQUEST_HEADERS:Host,"
            .. "ctl:ruleRemoveById=941100",
        check = function(controls)
            ok(#controls == 3, "three controls extracted, got " .. #controls)
        end,
    },
    {
        name = "no ctl directives → empty controls",
        actions = "id:9507106,phase:1,pass,t:none,nolog",
        check = function(controls)
            ok(#controls == 0, "empty controls when no ctl present")
        end,
    },
    {
        name = "ctl: with unknown directive ignored",
        actions = "id:9507107,phase:1,pass,nolog,ctl:ruleRemoveByMsg=somemsg",
        check = function(controls)
            ok(#controls == 0, "unknown ctl ignored")
        end,
    },
}

for _, case in ipairs(cases) do
    print("- " .. case.name)
    local controls = seclang.__get_rule_controls(case.actions)
    case.check(controls)
end

-- Standalone __parse_ctl_target checks
print("- __parse_ctl_target")
ok(seclang.__parse_ctl_target("ARGS:foo") == "request.arg.value:foo",
   "ARGS:foo → request.arg.value:foo")
ok(seclang.__parse_ctl_target("REQUEST_HEADERS:X-Forwarded-For") == "request.header.value:x-forwarded-for",
   "REQUEST_HEADERS lowercased")
ok(seclang.__parse_ctl_target("ARGS") == "request.arg.value",
   "bare ARGS")
ok(seclang.__parse_ctl_target("") == nil, "empty target → nil")
ok(seclang.__parse_ctl_target(nil) == nil, "nil target → nil")

-- parse_isolated end-to-end: a synthetic SecLang blob in the
-- wp-rule-exclusions shape parses into a *fresh* `{id = rule}` table
-- with the ctl:* derivatives surfaced on `rule.rule_control`. Critical
-- that the module-level rules table is left untouched so the long-lived
-- CRS pack loaded at init_worker is never corrupted by per-request
-- dynamic-rule parsing.
print("- parse_isolated end-to-end")

local sample = [[
SecRule REQUEST_FILENAME "@beginsWith /wp-login.php" \
    "id:9999100,phase:1,pass,t:none,nolog,\
    ctl:ruleRemoveTargetById=941100;ARGS:bypass_param"

SecRule REQUEST_URI "@beginsWith /wp-admin-bypass" \
    "id:9999101,phase:1,pass,t:none,nolog,\
    ctl:ruleEngine=Off"
]]

local parsed = seclang.parse_isolated(sample)

-- Result table is keyed by rule id (string).
ok(parsed["9999100"] ~= nil, "rule 9999100 parsed")
ok(parsed["9999101"] ~= nil, "rule 9999101 parsed")

-- 9999100 should have a remove_target_from_rule_by_id control
-- pointing at 941100 / request.arg.value:bypass_param.
local r1 = parsed["9999100"] or {}
local c1 = deep_find(r1.rule_control or {}, function(x)
    return x.remove_target_from_rule_by_id
        and x.remove_target_from_rule_by_id.rule_id == "941100"
        and x.remove_target_from_rule_by_id.target == "request.arg.value:bypass_param"
end)
ok(c1 ~= nil, "9999100 carries the ruleRemoveTargetById control")

-- 9999101 should have engine_off=true.
local r2 = parsed["9999101"] or {}
local c2 = deep_find(r2.rule_control or {}, function(x) return x.engine_off == true end)
ok(c2 ~= nil, "9999101 carries the engine_off control")

-- Second call to parse_isolated must NOT contain the rules from the
-- first call — isolation across calls is the whole point.
local second = seclang.parse_isolated([[
SecRule REQUEST_URI "@beginsWith /other" \
    "id:9999200,phase:1,pass,t:none,nolog,ctl:ruleEngine=Off"
]])
ok(second["9999100"] == nil, "second parse does not leak prior rules")
ok(second["9999200"] ~= nil, "second parse contains its own rule")

print(string.format("\n%d test(s) failed", fails))
os.exit(fails == 0 and 0 or 1)
