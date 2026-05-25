-- ka-unittest/rule_overrides.lua
--
-- Unit-test the selector grammar and the action/response override
-- resolver. The selector decides whether a per-rule override entry
-- applies to a given matched rule; the resolver produces the
-- effective action for that rule.
--
-- We replicate `selector_matches` and `apply_action_and_response_overrides`
-- inline (same convention as set_variable_action.lua and
-- fix_matched_parts.lua) so the test stays free of kong/ngx globals.
-- KEEP IN SYNC with kong/plugins/karna/handler.lua.

local fails = 0
local function ok(cond, name)
    if cond then
        print("  ok  - " .. name)
    else
        print("  FAIL- " .. name)
        fails = fails + 1
    end
end

-- ============================================================
-- SUT — copy from handler.lua. Drop kong / engine globals; the
-- macro resolution path (engine:replace_variable_in_string) is
-- replaced with an identity mock since the unit tests don't need
-- request-context resolution.
-- ============================================================
local DEFAULT_FIX_PATTERN = [=[[<>"';&|`$()]]=]

local function selector_matches(selector, rule)
    if not selector or not rule then return false end

    if selector.except_ids and rule.id then
        for _, eid in ipairs(selector.except_ids) do
            if tostring(eid) == tostring(rule.id) then return false end
        end
    end
    if selector.except_tags and rule.tags then
        for _, etag in ipairs(selector.except_tags) do
            for _, rtag in ipairs(rule.tags) do
                if rtag == etag then return false end
            end
        end
    end

    local has_positive = (selector.ids and #selector.ids > 0)
                      or (selector.id_ranges and #selector.id_ranges > 0)
                      or (selector.tags and #selector.tags > 0)
                      or (selector.any == true)
    if not has_positive then return false end
    if selector.any == true then return true end

    if selector.ids and rule.id then
        for _, sid in ipairs(selector.ids) do
            if tostring(sid) == tostring(rule.id) then return true end
        end
    end
    if selector.id_ranges and rule.id then
        local rule_id_n = tonumber(rule.id)
        if rule_id_n then
            for _, rng in ipairs(selector.id_ranges) do
                local lo, hi = string.match(rng, "^(%d+)%-(%d+)$")
                if lo and hi and rule_id_n >= tonumber(lo) and rule_id_n <= tonumber(hi) then
                    return true
                end
            end
        end
    end
    if selector.tags and rule.tags then
        for _, stag in ipairs(selector.tags) do
            for _, rtag in ipairs(rule.tags) do
                if rtag == stag then return true end
            end
        end
    end

    return false
end

-- engine.replace_variable_in_string mock — identity (no %{var}
-- resolution needed for these unit tests).
local engine_mock = {
    replace_variable_in_string = function(self, s) return s end,
}

local function apply_overrides(action_overrides, response_overrides, rule)
    local effective = rule.action
    if (#action_overrides == 0) and (#response_overrides == 0) then return effective end

    if #action_overrides > 0 then
        for _, ov in ipairs(action_overrides) do
            if selector_matches(ov.selector, rule) then
                local t = ov.action and ov.action.type
                if t == "fix" then
                    effective = {
                        fix_matched_parts = {
                            remove_chars_pattern = ov.action.remove_chars_pattern or DEFAULT_FIX_PATTERN,
                        },
                    }
                elseif t == "passthrough" then
                    effective = { setvar = {} }
                elseif t == "block" then
                    local base = (rule.action and rule.action.fixed_response) or {
                        status_code = 403,
                        body = "Forbidden\r\n",
                        headers = { ["content-type"] = "text/plain" },
                    }
                    effective = { fixed_response = {
                        status_code = base.status_code,
                        body = base.body,
                        headers = base.headers,
                    } }
                end
                break
            end
        end
    end

    if #response_overrides > 0 and effective and effective.fixed_response then
        for _, ov in ipairs(response_overrides) do
            if selector_matches(ov.selector, rule) then
                local fr = effective.fixed_response
                local new_fr = {
                    status_code = fr.status_code,
                    body = fr.body,
                    headers = {},
                }
                if fr.headers then
                    for k, v in pairs(fr.headers) do new_fr.headers[k] = v end
                end
                if ov.response.status_code then new_fr.status_code = ov.response.status_code end
                if ov.response.body then
                    new_fr.body = engine_mock:replace_variable_in_string(ov.response.body)
                end
                if ov.response.headers then
                    for k, v in pairs(ov.response.headers) do new_fr.headers[k] = v end
                end
                effective = { fixed_response = new_fr }
                if rule.action and rule.action.setvar then effective.setvar = rule.action.setvar end
                if rule.action and rule.action.fix_matched_parts then effective.fix_matched_parts = rule.action.fix_matched_parts end
                break
            end
        end
    end

    return effective
end

-- ============================================================
-- selector tests
-- ============================================================
print("- selector.ids exact match")
ok(selector_matches({ ids = { "941100" } }, { id = "941100" }), "id matches as string")
ok(selector_matches({ ids = { 941100 } }, { id = "941100" }), "id matches when selector uses number")
ok(not selector_matches({ ids = { "941100" } }, { id = "941200" }), "id mismatch returns false")

print("- selector.id_ranges hyphen range")
ok(selector_matches({ id_ranges = { "941000-941999" } }, { id = "941100" }), "id in range")
ok(selector_matches({ id_ranges = { "941000-941999" } }, { id = "941999" }), "id at upper bound")
ok(selector_matches({ id_ranges = { "941000-941999" } }, { id = "941000" }), "id at lower bound")
ok(not selector_matches({ id_ranges = { "941000-941999" } }, { id = "942000" }), "id out of range")

print("- selector.tags any-of")
ok(selector_matches({ tags = { "attack-xss" } }, { id = "941100", tags = { "attack-xss", "paranoia-level/1" } }), "tag intersects")
ok(not selector_matches({ tags = { "attack-rce" } }, { id = "941100", tags = { "attack-xss" } }), "no tag overlap")

print("- selector.except_ids excludes")
ok(not selector_matches(
       { ids = { "941100" }, except_ids = { "941100" } },
       { id = "941100" }
   ), "exact id excluded even when positive ids match")
ok(selector_matches(
       { ids = { "941100", "941200" }, except_ids = { "941100" } },
       { id = "941200" }
   ), "other positive id still matches")

print("- selector.except_tags excludes")
ok(not selector_matches(
       { tags = { "attack-xss" }, except_tags = { "OWASP_CRS/HIGH-FP-RISK" } },
       { id = "941100", tags = { "attack-xss", "OWASP_CRS/HIGH-FP-RISK" } }
   ), "rule excluded by tag")

print("- selector.any=true with except_*")
ok(selector_matches({ any = true }, { id = "941100" }), "any=true matches every rule")
ok(not selector_matches(
       { any = true, except_ids = { "941100" } },
       { id = "941100" }
   ), "any=true honored with except_ids")

print("- selector empty (no positive criteria, no any) → never matches")
ok(not selector_matches({}, { id = "941100" }), "empty selector matches nothing")
ok(not selector_matches({ except_ids = { "X" } }, { id = "941100" }), "only except_* with no positive matches nothing")

-- ============================================================
-- override tests
-- ============================================================
print("- action override: block → fix")
local rule = {
    id = "941100",
    tags = { "attack-xss" },
    action = { fixed_response = { status_code = 403, body = "Forbidden\r\n", headers = {} } },
}
local eff = apply_overrides(
    { { selector = { tags = { "attack-xss" } }, action = { type = "fix", remove_chars_pattern = "[<>]" } } },
    {},
    rule
)
ok(eff.fix_matched_parts ~= nil, "fix_matched_parts present")
ok(eff.fix_matched_parts.remove_chars_pattern == "[<>]", "pattern carried through")
ok(eff.fixed_response == nil, "fixed_response removed (sanitize takes precedence)")

print("- action override: block → fix without pattern uses default")
local eff2 = apply_overrides(
    { { selector = { ids = { "941100" } }, action = { type = "fix" } } },
    {},
    rule
)
ok(eff2.fix_matched_parts.remove_chars_pattern == DEFAULT_FIX_PATTERN, "default pattern applied")

print("- action override: block → passthrough")
local eff3 = apply_overrides(
    { { selector = { ids = { "941100" } }, action = { type = "passthrough" } } },
    {},
    rule
)
ok(eff3.fixed_response == nil and eff3.fix_matched_parts == nil, "no terminal action — pure log")

print("- action override: only first matching wins")
local eff4 = apply_overrides(
    {
        { selector = { ids = { "941100" } }, action = { type = "fix" } },
        { selector = { ids = { "941100" } }, action = { type = "passthrough" } },
    },
    {},
    rule
)
ok(eff4.fix_matched_parts ~= nil, "first override won (fix), not passthrough")

print("- response override: body / status / headers customised")
local eff5 = apply_overrides(
    {},
    { { selector = { ids = { "941100" } },
        response = { status_code = 451, body = "nope", headers = { ["x-blocked-by"] = "karna" } } } },
    rule
)
ok(eff5.fixed_response.status_code == 451, "status_code overridden")
ok(eff5.fixed_response.body == "nope", "body overridden")
ok(eff5.fixed_response.headers["x-blocked-by"] == "karna", "header added")

print("- response override doesn't fire when effective action isn't a block")
local rule_fix = { id = "X", tags = {}, action = { fix_matched_parts = { remove_chars_pattern = "[x]" } } }
local eff6 = apply_overrides(
    {},
    { { selector = { ids = { "X" } }, response = { status_code = 451 } } },
    rule_fix
)
ok(eff6.fix_matched_parts ~= nil, "fix preserved")
ok(eff6.fixed_response == nil, "response override skipped on non-block rule")

print("- combined: action override (fix) shadows response override")
local eff7 = apply_overrides(
    { { selector = { tags = { "attack-xss" } }, action = { type = "fix" } } },
    { { selector = { ids = { "941100" } }, response = { status_code = 451 } } },
    rule
)
ok(eff7.fix_matched_parts ~= nil and eff7.fixed_response == nil,
   "action override took rule out of block path before response override could fire")

print("- non-matching selector → original action untouched")
local eff8 = apply_overrides(
    { { selector = { ids = { "999999" } }, action = { type = "fix" } } },
    {},
    rule
)
ok(eff8 == rule.action, "same reference (no copy) when nothing matches")

print(string.format("\n%d test(s) failed", fails))
os.exit(fails == 0 and 0 or 1)
