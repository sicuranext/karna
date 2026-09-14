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
    {
        name = "ruleEngine=DetectionOnly",
        actions = "id:9507108,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly",
        check = function(controls)
            local c = deep_find(controls, function(x) return x.detection_only == true end)
            ok(c ~= nil, "detection_only=true emitted")
            ok(deep_find(controls, function(x) return x.engine_off == true end) == nil,
               "DetectionOnly does not also emit engine_off")
        end,
    },
    {
        -- Off is the stronger of the two; a rule declaring both must not end up
        -- merely detection-only.
        name = "ruleEngine=Off wins over =DetectionOnly",
        actions = "id:9507109,phase:1,pass,nolog,ctl:ruleEngine=Off,ctl:ruleEngine=DetectionOnly",
        check = function(controls)
            ok(deep_find(controls, function(x) return x.engine_off == true end) ~= nil,
               "engine_off emitted")
            ok(deep_find(controls, function(x) return x.detection_only == true end) == nil,
               "detection_only NOT emitted alongside engine_off")
        end,
    },
    {
        name = "ruleRemoveByTag",
        actions = "id:9507110,phase:1,pass,nolog,ctl:ruleRemoveByTag=attack-sqli",
        check = function(controls)
            local c = deep_find(controls, function(x)
                return x.remove_rules_by_tag and x.remove_rules_by_tag.tag == "attack-sqli"
            end)
            ok(c ~= nil, "remove_rules_by_tag.tag=attack-sqli")
        end,
    },
    {
        -- CRS 905100 / 905110 shape: remove the whole ruleset by its umbrella tag.
        name = "ruleRemoveByTag=OWASP_CRS",
        actions = "id:9507111,phase:1,pass,nolog,ctl:ruleRemoveByTag=OWASP_CRS,ctl:auditEngine=Off",
        check = function(controls)
            local c = deep_find(controls, function(x)
                return x.remove_rules_by_tag and x.remove_rules_by_tag.tag == "OWASP_CRS"
            end)
            ok(c ~= nil, "remove_rules_by_tag.tag=OWASP_CRS")
        end,
    },
    {
        name = "requestBodyAccess=Off",
        actions = "id:9507112,phase:1,pass,nolog,ctl:requestBodyAccess=Off",
        check = function(controls)
            local c = deep_find(controls, function(x) return x.body_access_off == true end)
            ok(c ~= nil, "body_access_off=true emitted")
        end,
    },
    {
        -- =On is the default state: nothing to record, and emitting a control
        -- would make an inert directive look like it did something.
        name = "requestBodyAccess=On emits nothing",
        actions = "id:9507113,phase:1,pass,nolog,ctl:requestBodyAccess=On",
        check = function(controls)
            ok(deep_find(controls, function(x) return x.body_access_off == true end) == nil,
               "no body_access_off for =On")
        end,
    },
    {
        -- Collection form, the shape CRS 4.x itself ships (942100 / 942450 /
        -- 932220 on REQUEST_COOKIES). The target has no `:<name>`: the whole
        -- collection goes. The parser must keep the bare namespace bare — the
        -- engine's remove_ctl_target recognises it as "empty the collection".
        name = "ruleRemoveTargetById with a bare REQUEST_COOKIES collection",
        actions = "id:9507114,phase:1,pass,nolog,ctl:ruleRemoveTargetById=942100;REQUEST_COOKIES",
        check = function(controls)
            local c = deep_find(controls, function(x)
                return x.remove_target_from_rule_by_id
                    and x.remove_target_from_rule_by_id.rule_id == "942100"
                    and x.remove_target_from_rule_by_id.target == "request.cookie.value"
            end)
            ok(c ~= nil, "REQUEST_COOKIES → bare request.cookie.value")
        end,
    },
    {
        name = "ruleRemoveTargetById with a bare REQUEST_COOKIES_NAMES collection",
        actions = "id:9507115,phase:1,pass,nolog,ctl:ruleRemoveTargetById=942450;REQUEST_COOKIES_NAMES",
        check = function(controls)
            local c = deep_find(controls, function(x)
                return x.remove_target_from_rule_by_id
                    and x.remove_target_from_rule_by_id.rule_id == "942450"
                    and x.remove_target_from_rule_by_id.target == "request.cookie.name"
            end)
            ok(c ~= nil, "REQUEST_COOKIES_NAMES → bare request.cookie.name")
        end,
    },
    {
        name = "ruleRemoveTargetByTag with a bare REQUEST_HEADERS collection",
        actions = "id:9507116,phase:1,pass,nolog,ctl:ruleRemoveTargetByTag=attack-sqli;REQUEST_HEADERS",
        check = function(controls)
            local c = deep_find(controls, function(x)
                return x.remove_target_rule_by_tag
                    and x.remove_target_rule_by_tag.tag == "attack-sqli"
                    and x.remove_target_rule_by_tag.name == "request.header.value"
            end)
            ok(c ~= nil, "REQUEST_HEADERS → bare request.header.value")
        end,
    },
    {
        -- The two forms side by side in one actions string, as the CRS
        -- 942450 exclusion is written: one field of ARGS, the whole cookie
        -- collection, and the cookie names collection.
        name = "mixed field and collection targets in one rule",
        actions = "id:9507117,phase:1,pass,nolog,"
            .. "ctl:ruleRemoveTargetById=942450;ARGS:token,"
            .. "ctl:ruleRemoveTargetById=942450;REQUEST_COOKIES,"
            .. "ctl:ruleRemoveTargetById=942450;REQUEST_COOKIES_NAMES",
        check = function(controls)
            ok(#controls == 3, "three controls extracted, got " .. #controls)
            local targets = {}
            for _, c in ipairs(controls) do
                if c.remove_target_from_rule_by_id then
                    targets[c.remove_target_from_rule_by_id.target] = true
                end
            end
            ok(targets["request.arg.value:token"] and targets["request.cookie.value"]
               and targets["request.cookie.name"], "field + two collections all mapped")
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
-- Bare collections: the ModSecurity name maps to the Karna namespace and stays
-- bare (no trailing `:`), which is what the engine's collection form keys on.
ok(seclang.__parse_ctl_target("REQUEST_COOKIES") == "request.cookie.value",
   "bare REQUEST_COOKIES → request.cookie.value")
ok(seclang.__parse_ctl_target("REQUEST_COOKIES_NAMES") == "request.cookie.name",
   "bare REQUEST_COOKIES_NAMES → request.cookie.name")
ok(seclang.__parse_ctl_target("REQUEST_HEADERS") == "request.header.value",
   "bare REQUEST_HEADERS → request.header.value")
ok(seclang.__parse_ctl_target("REQUEST_HEADERS_NAMES") == "request.header.name",
   "bare REQUEST_HEADERS_NAMES → request.header.name")
ok(seclang.__parse_ctl_target("ARGS_GET") == "request.query.value",
   "bare ARGS_GET → request.query.value")
ok(seclang.__parse_ctl_target("ARGS_NAMES") == "request.arg.name",
   "bare ARGS_NAMES → request.arg.name")
ok(seclang.__parse_ctl_target("REQUEST_COOKIES:session") == "request.cookie.value:session",
   "REQUEST_COOKIES:session keeps the field")
ok(seclang.__parse_ctl_target("NOT_A_VARIABLE") == nil,
   "unknown bare name → nil (directive dropped, never a stray literal)")
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

-- CRS 4.x shape: an exclusion rule carrying the bare collection directives.
-- The controls must land on the parsed rule with the namespaces bare, exactly
-- as the engine expects them.
local crs_shape = seclang.parse_isolated([[
SecRule REQUEST_FILENAME "@endsWith /example-endpoint" \
    "id:9999300,phase:1,pass,t:none,nolog,\
    ctl:ruleRemoveTargetById=942100;REQUEST_COOKIES,\
    ctl:ruleRemoveTargetById=942450;REQUEST_COOKIES,\
    ctl:ruleRemoveTargetById=942450;REQUEST_COOKIES_NAMES,\
    ctl:ruleRemoveTargetById=932220;REQUEST_COOKIES"
]])
local r3 = crs_shape["9999300"] or {}
local seen = {}
for _, c in ipairs(r3.rule_control or {}) do
    local t = c.remove_target_from_rule_by_id
    if t then seen[t.rule_id .. ";" .. t.target] = true end
end
ok(seen["942100;request.cookie.value"] and seen["942450;request.cookie.value"]
   and seen["942450;request.cookie.name"] and seen["932220;request.cookie.value"],
   "CRS-shaped rule carries all four bare-collection controls")

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
