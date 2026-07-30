-- ka-unittest/rule_control_runtime.lua
--
-- Guards the per-request rule-control STORE and its readers — the half of the
-- ctl:* pipeline that seclang_ctl_directives.lua does not cover (that one stops
-- at "the parser emitted the right control table"; this one starts at "the
-- applier wrote it into kong.ctx.plugin.rule_controls and the reader acted on
-- it").
--
-- Three regressions are pinned here, all of the same silent-no-op family that
-- made ctl:ruleRemoveTargetByTag on a non-OWASP_CRS tag dead for so long:
--
--   1. remove_rules_by_tag — the reader walks rule.tags only when
--      `_has_removed_tags` is armed. That gate exists for perf (the reader runs
--      once per rule per request, ~300 CRS rules deep), and a gate is exactly
--      the kind of thing that silently disables a feature if the applier forgets
--      to set it. Both directions are tested.
--   2. remove_target_rule_by_tag on an arbitrary tag — routed through
--      rule_controls.tags[<tag>].target and only applied to rules carrying that
--      tag. OWASP_CRS keeps its own "all rules" fast path.
--   3. detection_only vs engine_blocking_mode — which combinations let a
--      terminal action through.
--
-- SUT is replicated inline (same convention as rule_overrides.lua,
-- wordpress_target_exclusion.lua, set_variable_action.lua) so the test needs no
-- kong/ngx globals. KEEP IN SYNC with:
--   kong/plugins/karna/modules/ka_engine.lua  __apply_rule_controls_inline,
--                                             __rule_control_rule_removed,
--                                             the rc_tag_names collection in
--                                             __match_rule_conditions_impl,
--                                             remove_ctl_target
--   kong/plugins/karna/handler.lua            detection_only_active,
--                                             rule_blocking_enabled
--
-- Run from repo root:
--   lua    ka-unittest/rule_control_runtime.lua
--   luajit ka-unittest/rule_control_runtime.lua

local string_find = string.find
local string_sub  = string.sub

local fails = 0
local function ok(cond, name)
    if cond then print("  ok  - " .. name)
    else print("  FAIL- " .. name); fails = fails + 1 end
end

-- ============================================================
-- SUT — the per-request store, as handler.lua:access initialises it
-- ============================================================
local function new_store()
    return {
        ids = {},
        ids_targets = {},
        tags = {},
        removed_tags = {},
        remove_target_from_all_rules = {},
        engine_off = false,
        detection_only = false,
        body_access_off = false,
    }
end

-- SUT — copy from ka_engine.lua:__apply_rule_controls_inline, with the
-- kong.ctx.plugin indirection replaced by an explicit `rc` argument.
local function apply_rule_controls(rc, controls)
    if not controls or not rc then return end
    for _, control in pairs(controls) do
        if control.remove_rule and control.remove_rule.rule_id then
            local id_spec = control.remove_rule.rule_id
            local lo, hi = string.match(id_spec, "^(%d+)%-(%d+)$")
            if lo and hi then
                local lo_n, hi_n = tonumber(lo), tonumber(hi)
                if lo_n and hi_n then
                    for n = lo_n, hi_n do
                        rc.ids[tostring(n)] = { action = "remove" }
                    end
                end
            else
                rc.ids[id_spec] = { action = "remove" }
            end
        end

        if control.remove_target_from_rule_by_id then
            local r = control.remove_target_from_rule_by_id
            if r.rule_id and r.target then
                if not rc.ids_targets[r.rule_id] then
                    rc.ids_targets[r.rule_id] = {}
                end
                table.insert(rc.ids_targets[r.rule_id], r.target)
            end
        end

        if control.remove_target_rule_by_tag and control.remove_target_rule_by_tag.tag then
            local rt = control.remove_target_rule_by_tag
            if rt.tag == "OWASP_CRS" then
                table.insert(rc.remove_target_from_all_rules, rt.name)
            else
                if not rc.tags[rt.tag] then
                    rc.tags[rt.tag] = { action = "remove_target", target = { rt.name } }
                else
                    table.insert(rc.tags[rt.tag].target, rt.name)
                end
                rc._has_tag_targets = true
            end
        end

        if control.remove_rules_by_tag and control.remove_rules_by_tag.tag then
            rc.removed_tags[control.remove_rules_by_tag.tag] = true
            rc._has_removed_tags = true
        end

        if control.detection_only then rc.detection_only = true end
        if control.body_access_off then rc.body_access_off = true end
        if control.engine_off then rc.engine_off = true end
    end
end

-- SUT — copy from ka_engine.lua:__rule_control_rule_removed
local function rule_removed(rc, rule)
    if rc.ids[rule.id] and rc.ids[rule.id]["action"] == "remove" then
        return true
    end
    if rc._has_removed_tags and rule.tags then
        for _, rule_tag in pairs(rule.tags) do
            if rc.removed_tags[rule_tag] then return true end
        end
    end
    return false
end

-- SUT — copy from ka_engine.lua:remove_ctl_target
local function remove_ctl_target(values, target, variable)
    if not values or type(target) ~= "string" then return end
    if values[target] ~= nil then values[target] = nil end
    local colon = string_find(target, ":", 1, true)
    if not colon then return end
    local t_ns   = string_sub(target, 1, colon - 1)
    local t_name = string_sub(target, colon + 1)
    if t_name == "" then return end
    if type(variable) ~= "string" then return end
    local vcolon = string_find(variable, ":", 1, true)
    local var_ns = vcolon and string_sub(variable, 1, vcolon - 1) or variable
    if t_ns ~= var_ns then return end
    for k in pairs(values) do
        if string_find(k, "%." .. t_name .. "$") or string_find(k, ":" .. t_name .. "$") then
            values[k] = nil
        end
    end
end

-- SUT — copy from ka_engine.lua:__match_rule_conditions_impl, the rc_tag_names
-- collection block, followed by the application loop.
local function apply_tag_targets(rc, rule, values, variable)
    local rc_tag_names
    if rc._has_tag_targets and rule.tags then
        for _, rule_tag in pairs(rule.tags) do
            local entry = rc.tags[rule_tag]
            if entry and entry.action == "remove_target" and entry.target then
                for _, t in pairs(entry.target) do
                    rc_tag_names = rc_tag_names or {}
                    rc_tag_names[#rc_tag_names + 1] = t
                end
            end
        end
    end
    if values and rc_tag_names then
        for _, nm in pairs(rc_tag_names) do
            remove_ctl_target(values, nm, variable)
        end
    end
end

-- SUT — copy from handler.lua
local function detection_only_active(rc) return (rc and rc.detection_only) == true end
local function rule_blocking_enabled(rc, engine_blocking_mode)
    if not engine_blocking_mode then return false end
    return not detection_only_active(rc)
end

local function has(values, k) return values[k] ~= nil end

-- ============================================================
print("- ctl:ruleRemoveByTag drops every rule carrying the tag")
-- ============================================================
local rc = new_store()
apply_rule_controls(rc, { { remove_rules_by_tag = { tag = "attack-sqli" } } })

ok(rc._has_removed_tags == true, "applier armed the _has_removed_tags gate")
ok(rule_removed(rc, { id = "942100", tags = { "application-multi", "attack-sqli" } }),
   "tagged rule is removed")
ok(not rule_removed(rc, { id = "941100", tags = { "application-multi", "attack-xss" } }),
   "differently-tagged rule survives")
ok(not rule_removed(rc, { id = "930100", tags = nil }),
   "rule with no tags at all survives (no crash on nil tags)")

print("- OWASP_CRS as a removal tag takes the whole ruleset out")
rc = new_store()
apply_rule_controls(rc, { { remove_rules_by_tag = { tag = "OWASP_CRS" } } })
ok(rule_removed(rc, { id = "942100", tags = { "OWASP_CRS", "attack-sqli" } }),
   "CRS rule removed (the 905100 / 901450 shape)")
ok(not rule_removed(rc, { id = "global-1", tags = { "global-pack" } }),
   "an untagged-by-OWASP_CRS custom rule is NOT removed")

-- The gate is a perf optimisation, so prove it is actually load-bearing: with
-- removed_tags populated but the flag down, the reader must skip the walk. If
-- this ever inverts, a forgotten flag becomes a silently disabled feature.
print("- the _has_removed_tags gate is load-bearing")
rc = new_store()
rc.removed_tags["attack-sqli"] = true          -- populated WITHOUT the flag
ok(not rule_removed(rc, { id = "942100", tags = { "attack-sqli" } }),
   "gate down → no tag walk (applier must set the flag)")
rc._has_removed_tags = true
ok(rule_removed(rc, { id = "942100", tags = { "attack-sqli" } }),
   "gate up → tag walk runs")

-- ============================================================
print("")
print("- ctl:ruleRemoveTargetByTag on an arbitrary tag (was a silent no-op)")
-- ============================================================
rc = new_store()
apply_rule_controls(rc, {
    { remove_target_rule_by_tag = { tag = "attack-sqli", name = "request.header.value:user-agent" } },
})
ok(rc._has_tag_targets == true, "applier armed the _has_tag_targets gate")
ok(rc.tags["attack-sqli"] ~= nil, "target filed under the tag, not the all-rules list")
ok(#rc.remove_target_from_all_rules == 0, "non-OWASP_CRS tag did NOT go to the all-rules fast path")

local sqli_rule = { id = "942100", tags = { "application-multi", "attack-sqli" } }
local xss_rule  = { id = "941100", tags = { "application-multi", "attack-xss" } }

local v = { ["request.header.value:user-agent"] = "' OR 1=1" }
apply_tag_targets(rc, sqli_rule, v, "request.header.value")
ok(not has(v, "request.header.value:user-agent"),
   "UA target removed for the attack-sqli rule")

v = { ["request.header.value:user-agent"] = "' OR 1=1" }
apply_tag_targets(rc, xss_rule, v, "request.header.value")
ok(has(v, "request.header.value:user-agent"),
   "UA target SURVIVES for the attack-xss rule — the exclusion is tag-scoped")

print("- multiple targets accumulate under one tag")
rc = new_store()
apply_rule_controls(rc, {
    { remove_target_rule_by_tag = { tag = "attack-rce", name = "request.header.value:user-agent" } },
    { remove_target_rule_by_tag = { tag = "attack-rce", name = "request.header.value:referer" } },
})
ok(#rc.tags["attack-rce"].target == 2, "both targets under attack-rce")
v = { ["request.header.value:user-agent"] = "x",
      ["request.header.value:referer"]    = "y",
      ["request.header.value:host"]       = "z" }
apply_tag_targets(rc, { id = "932100", tags = { "attack-rce" } }, v, "request.header.value")
ok(not has(v, "request.header.value:user-agent"), "user-agent removed")
ok(not has(v, "request.header.value:referer"),    "referer removed")
ok(has(v, "request.header.value:host"),           "host untouched")

print("- the namespace gate still holds for tag targets")
rc = new_store()
apply_rule_controls(rc, {
    { remove_target_rule_by_tag = { tag = "attack-sqli", name = "request.arg.value:pwd" } },
})
v = { ["request.header.value:pwd"] = "' OR 1=1" }
apply_tag_targets(rc, sqli_rule, v, "request.header.value")
ok(has(v, "request.header.value:pwd"),
   "an ARGS-scoped tag exclusion cannot silence a header of the same name")

print("- the _has_tag_targets gate is load-bearing")
rc = new_store()
rc.tags["attack-sqli"] = { action = "remove_target", target = { "request.header.value:user-agent" } }
v = { ["request.header.value:user-agent"] = "x" }
apply_tag_targets(rc, sqli_rule, v, "request.header.value")
ok(has(v, "request.header.value:user-agent"), "gate down → no removal")

-- ============================================================
print("")
print("- ctl:ruleEngine=DetectionOnly vs engine_blocking_mode")
-- ============================================================
rc = new_store()
ok(rule_blocking_enabled(rc, true),  "blocking service, no control → terminal actions fire")
ok(not rule_blocking_enabled(rc, false), "detection service → terminal actions suppressed")

apply_rule_controls(rc, { { detection_only = true } })
ok(rc.detection_only == true, "applier set detection_only")
ok(not rule_blocking_enabled(rc, true),
   "blocking service + DetectionOnly → terminal actions suppressed")
ok(detection_only_active(rc), "fix_matched_parts sanitising is suppressed too")

-- engine_off is the stronger control and is stored independently: a request can
-- be detection-only without being bypassed, and vice versa.
print("- engine_off and detection_only are independent flags")
rc = new_store()
apply_rule_controls(rc, { { engine_off = true } })
ok(rc.engine_off == true and rc.detection_only == false,
   "engine_off alone does not imply detection_only")

-- ============================================================
print("")
print("- ctl:requestBodyAccess=Off")
-- ============================================================
rc = new_store()
ok(rc.body_access_off == false, "off by default")
apply_rule_controls(rc, { { body_access_off = true } })
ok(rc.body_access_off == true, "applier set body_access_off")

-- The getters key their per-request cache on this flag rather than invalidating
-- it, because the always-on body-parser gate warms the cache before any rule
-- control exists. Pin the key derivation so a flipped flag can never read back
-- a body-bearing entry.
local function body_cache_key(rc_, try_b64)
    if (rc_ and rc_.body_access_off) == true then
        return try_b64 and "b64:nobody" or "raw:nobody"
    end
    return try_b64 and "b64" or "raw"
end
ok(body_cache_key(new_store(), false) == "raw", "normal request → raw")
ok(body_cache_key(new_store(), true)  == "b64", "normal request, b64 → b64")
ok(body_cache_key(rc, false) == "raw:nobody", "body_access_off → distinct key")
ok(body_cache_key(rc, true)  == "b64:nobody", "body_access_off, b64 → distinct key")
ok(body_cache_key(rc, false) ~= body_cache_key(new_store(), false),
   "a warm pre-control entry can never be read back after the flag flips")

-- ============================================================
print("")
print("- controls accumulate across several matching exclusion rules")
-- ============================================================
-- The controls path is multi-match: every matching exclusion contributes. A
-- second apply must not clobber the first.
rc = new_store()
apply_rule_controls(rc, { { remove_rule = { rule_id = "920170" } } })
apply_rule_controls(rc, { { remove_rules_by_tag = { tag = "attack-sqli" } },
                          { detection_only = true } })
apply_rule_controls(rc, { { remove_rule = { rule_id = "932260" } } })
ok(rule_removed(rc, { id = "920170", tags = {} }), "first pass id removal survived")
ok(rule_removed(rc, { id = "932260", tags = {} }), "third pass id removal applied")
ok(rule_removed(rc, { id = "942100", tags = { "attack-sqli" } }), "tag removal applied")
ok(rc.detection_only == true, "detection_only survived")

print(string.format("\n%d test(s) failed", fails))
os.exit(fails == 0 and 0 or 1)
