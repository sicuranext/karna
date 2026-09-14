-- ka-unittest/rule_control_runtime.lua
--
-- Guards the per-request rule-control STORE and its readers — the half of the
-- ctl:* pipeline that seclang_ctl_directives.lua does not cover (that one stops
-- at "the parser emitted the right control table"; this one starts at "the
-- applier wrote it into kong.ctx.plugin.rule_controls and the reader acted on
-- it").
--
-- Pinned here:
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
--   4. target removal, all three shapes of remove_ctl_target:
--        * the COLLECTION form (`request.cookie.value`, ModSecurity
--          `ctl:ruleRemoveTargetById=<id>;REQUEST_COOKIES`, which CRS 4.x
--          itself ships and which used to be a silent no-op);
--        * the PER-NAME form now stripping the keys the resolver DERIVED from
--          the field (JSON expansion, base64 variant, indexed duplicates);
--        * the namespace gate, unchanged: a cookie target never touches a
--          header or an argument of the same name.
--   5. the same removals end to end through `__match_rule_conditions`, on all
--      three per-request paths (by id, by tag, OWASP_CRS all-rules), including
--      "REQUEST_COOKIES|ARGS still matches on ARGS after the cookie collection
--      is removed" and the copy-on-read guarantee: a removal in one rule never
--      changes what the next rule sees, with the CSE fast path on.
--
-- The engine functions under test are the REAL ones — __apply_rule_controls_inline,
-- __rule_control_rule_removed, __remove_ctl_target, __match_rule_conditions —
-- loaded through ka-unittest/_engine_harness.lua. This file used to carry inline
-- copies of them and drifted. The two handler.lua helpers (detection_only_active,
-- rule_blocking_enabled) and body_cache_key are still copied: KEEP IN SYNC with
--   kong/plugins/karna/handler.lua          detection_only_active, rule_blocking_enabled
--   kong/plugins/karna/modules/ka_engine.lua body_cache_key
--
-- Run from repo root:
--   lua    ka-unittest/rule_control_runtime.lua
--   luajit ka-unittest/rule_control_runtime.lua

local H = dofile("./ka-unittest/_engine_harness.lua")
local engine = H.engine

local fails = 0
local function ok(cond, name, detail)
    if cond then print("  ok  - " .. name)
    else print("  FAIL- " .. name .. (detail and ("  (" .. tostring(detail) .. ")") or "")); fails = fails + 1 end
end
local function has(values, k) return values ~= nil and values[k] ~= nil end
local function count(t) local n = 0; if type(t) == "table" then for _ in pairs(t) do n = n + 1 end end; return n end

-- ============================================================
-- SUT bindings
-- ============================================================
-- The store is per request, on kong.ctx.plugin. `new_store()` is the shape
-- handler.lua:access creates; the harness installs a fresh one on reset().
local new_store = H.new_store

-- The applier reads the store from kong.ctx.plugin.rule_controls; bind an
-- explicit store for the tests that build one by hand.
local function apply_rule_controls(rc, controls, rule_id)
    kong.ctx.plugin.rule_controls = rc
    engine.__apply_rule_controls_inline(controls, rule_id)
end
local function rule_removed(rc, rule)
    kong.ctx.plugin.rule_controls = rc
    return engine:__rule_control_rule_removed(rule)
end
local remove_ctl_target = engine.__remove_ctl_target

-- The rc_tag_names collection block of __match_rule_conditions_impl, then the
-- application loop (the end-to-end section below drives the real one).
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
    if rc and rc.engine_on == true then return true end
    if not engine_blocking_mode then return false end
    return not detection_only_active(rc)
end

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
print("- collection form: REQUEST_COOKIES empties the cookie map (plain + JSON + base64)")
-- ============================================================
-- What the cookie resolver emits for `sid=abc; prefs={"k":"YWJj"}` with the
-- base64 pass on: plain value, cookie names, the JSON expansion and its
-- `_ka_b64_decoded` variant. None of the derived keys end in `:<name>`.
local function cookie_map()
    return {
        ["request.cookie.name:sid"]                           = "sid",
        ["request.cookie.value:sid"]                          = "abc",
        ["request.cookie.name:prefs"]                         = "prefs",
        ["request.cookie.json.prefs.value:k"]                 = "YWJj",
        ["request.cookie.json.prefs.name:k"]                  = "k",
        ["request.cookie.json.prefs.value:k_ka_b64_decoded"]  = "abc",
    }
end
v = cookie_map()
remove_ctl_target(v, "request.cookie.value", "request.cookie.value")
ok(count(v) == 0, "bare request.cookie.value while resolving request.cookie.value → nothing left", count(v))

print("- collection form: REQUEST_COOKIES_NAMES")
v = { ["request.cookie.name:sid"] = "sid", ["request.cookie.name:prefs"] = "prefs" }
remove_ctl_target(v, "request.cookie.name", "request.cookie.name")
ok(count(v) == 0, "bare request.cookie.name while resolving request.cookie.name → nothing left")
-- Karna's cookie VALUE map also carries the names, so REQUEST_COOKIES_NAMES
-- must take exactly those out of it and leave the values in place.
v = cookie_map()
remove_ctl_target(v, "request.cookie.name", "request.cookie.value")
ok(not has(v, "request.cookie.name:sid") and not has(v, "request.cookie.name:prefs"),
   "…and strips the folded name keys out of the value map")
ok(has(v, "request.cookie.value:sid") and has(v, "request.cookie.json.prefs.value:k"),
   "…while the cookie values stay (REQUEST_COOKIES was not excluded)")
-- and the other way round: REQUEST_COOKIES does not reach a names-only map
v = { ["request.cookie.name:sid"] = "sid" }
remove_ctl_target(v, "request.cookie.value", "request.cookie.name")
ok(has(v, "request.cookie.name:sid"), "REQUEST_COOKIES does not empty a REQUEST_COOKIES_NAMES resolution")

print("- collection form: ARGS empties query + body, ARGS_GET only the query half")
local function args_map()
    return {
        ["request.query.value:q"]                              = "1",
        ["request.query.name:q"]                               = "q",
        ["request.query.value:q_ka_b64_decoded"]               = "\x00\x01",
        ["request.query.json:cfg.value:a"]                     = "x",
        ["request.query.json:cfg.name:a"]                      = "a",
        ["request.query.value:__ka_path_confusion_1"]          = "hidden",
        ["request.body.urlencode.value:pwd"]                   = "s3cret",
        ["request.body.urlencode.name:pwd"]                    = "pwd",
        ["request.body.json.value:user.name"]                  = "bob",
        ["request.body.json.name:user.name"]                   = "user.name",
        ["request.body.multipart.value:file_desc"]             = "d",
        ["request.body.multipart.name:file_desc"]              = "file_desc",
    }
end
v = args_map()
remove_ctl_target(v, "request.arg.value", "request.arg.value")
ok(count(v) == 0, "bare request.arg.value while resolving request.arg.value → nothing left", count(v))

v = args_map()
remove_ctl_target(v, "request.query.value", "request.arg.value")
for k in pairs(args_map()) do
    if k:find("^request%.query%.") then
        ok(not has(v, k), "ARGS_GET folded into ARGS strips " .. k)
    else
        ok(has(v, k), "ARGS_GET folded into ARGS keeps " .. k)
    end
end

v = args_map()
remove_ctl_target(v, "request.arg.name", "request.arg.value")
ok(not has(v, "request.query.name:q") and not has(v, "request.body.urlencode.name:pwd")
   and not has(v, "request.body.json.name:user.name") and not has(v, "request.query.json:cfg.name:a"),
   "ARGS_NAMES folded into ARGS strips every .name: key")
ok(has(v, "request.query.value:q") and has(v, "request.body.urlencode.value:pwd")
   and has(v, "request.body.json.value:user.name"), "…and keeps every value")

v = args_map()
remove_ctl_target(v, "request.body.json.value", "request.arg.value")
ok(not has(v, "request.body.json.value:user.name") and not has(v, "request.body.json.name:user.name"),
   "Karna-native request.body.json.value folded into ARGS strips the JSON body keys")
ok(has(v, "request.query.value:q") and has(v, "request.body.urlencode.value:pwd"),
   "…and nothing else")

print("- collection form: the namespace gate")
v = { ["request.header.value:sid"] = "abc", ["request.header.value:host"] = "app.example" }
remove_ctl_target(v, "request.cookie.value", "request.header.value")
ok(count(v) == 2, "REQUEST_COOKIES never empties the header map (a header named like a cookie survives)")
v = cookie_map()
remove_ctl_target(v, "request.header.value", "request.cookie.value")
ok(count(v) == count(cookie_map()), "REQUEST_HEADERS never empties the cookie map")
v = cookie_map()
remove_ctl_target(v, "request.arg.value", "request.cookie.value")
ok(count(v) == count(cookie_map()), "ARGS never empties the cookie map")
v = { ["request.query.value:q"] = "1" }
remove_ctl_target(v, "request.arg.value", "request.query.value")
ok(has(v, "request.query.value:q"),
   "ARGS does not reach an ARGS_GET resolution (a superset is not folded into its part — ModSecurity semantics)")
v = { ["request.header.value:host"] = "app.example" }
remove_ctl_target(v, "request.header.value", "request.header.value:host")
ok(count(v) == 0, "REQUEST_HEADERS empties a single-header resolution (request.header.value:host)")

-- ============================================================
print("")
print("- per-name form: REQUEST_COOKIES:prefs strips the JSON-derived keys too")
-- ============================================================
v = cookie_map()
remove_ctl_target(v, "request.cookie.value:prefs", "request.cookie.value")
ok(not has(v, "request.cookie.json.prefs.value:k"),                "JSON expansion value:k removed")
ok(not has(v, "request.cookie.json.prefs.name:k"),                 "JSON expansion name:k removed")
ok(not has(v, "request.cookie.json.prefs.value:k_ka_b64_decoded"), "base64 variant removed")
ok(not has(v, "request.cookie.name:prefs"),                        "cookie name key removed (suffix, as before)")
ok(has(v, "request.cookie.value:sid") and has(v, "request.cookie.name:sid"), "the other cookie survives")

print("- per-name form: a cookie name that prefixes another")
v = { ["request.cookie.json.prefs.value:k"] = "1", ["request.cookie.json.prefs2.value:k"] = "2",
      ["request.cookie.value:prefs2"] = "x" }
remove_ctl_target(v, "request.cookie.value:prefs", "request.cookie.value")
ok(not has(v, "request.cookie.json.prefs.value:k"), "prefs JSON keys removed")
ok(has(v, "request.cookie.json.prefs2.value:k") and has(v, "request.cookie.value:prefs2"),
   "prefs2 (a different cookie) untouched — the derived prefix ends at the dot")

print("- per-name form: ARGS:cfg strips the JSON-in-urlencoded expansion, base64 variant, duplicates")
v = {
    ["request.query.value:cfg"]                    = '{"a":"x"}',
    ["request.query.name:cfg"]                     = "cfg",
    ["request.query.json:cfg.value:a"]             = "x",
    ["request.query.json:cfg.name:a"]              = "a",
    ["request.query.value:cfg_ka_b64_decoded"]     = "garbage",
    ["request.body.urlencode.value:cfg"]           = "y",
    ["request.body.urlencode.value:cfg:2"]         = "second occurrence",
    ["request.body.urlencode.json:cfg.value:b"]    = "z",
    ["request.query.value:cfg2"]                   = "keep",
    ["request.query.value:mycfg"]                  = "keep",
    ["request.body.json.value:cfg.child"]          = "keep (a JSON path UNDER cfg is not the field cfg)",
}
remove_ctl_target(v, "request.arg.value:cfg", "request.arg.value")
ok(not has(v, "request.query.value:cfg") and not has(v, "request.query.name:cfg"), "plain query keys removed")
ok(not has(v, "request.query.json:cfg.value:a") and not has(v, "request.query.json:cfg.name:a"),
   "query JSON-in-urlencoded expansion removed")
ok(not has(v, "request.query.value:cfg_ka_b64_decoded"), "base64 variant removed")
ok(not has(v, "request.body.urlencode.value:cfg"), "body plain key removed")
ok(not has(v, "request.body.urlencode.value:cfg:2"), "indexed duplicate removed")
ok(not has(v, "request.body.urlencode.json:cfg.value:b"), "body JSON-in-urlencoded expansion removed")
ok(has(v, "request.query.value:cfg2") and has(v, "request.query.value:mycfg"), "cfg2 / mycfg survive")
ok(has(v, "request.body.json.value:cfg.child"), "a JSON path under cfg is not stripped")

print("- per-name form: names compare lowercase (every resolver stores lowercase names)")
v = { ["request.body.urlencode.value:user_login"] = "admin", ["request.query.json:user_login.value:a"] = "1" }
remove_ctl_target(v, "request.arg.value:User_Login", "request.arg.value")
ok(count(v) == 0, "ARGS:User_Login strips …:user_login and its expansion")

print("- per-name form: the namespace gate")
v = { ["request.header.value:prefs"] = "x", ["request.header.value:cfg"] = "y" }
remove_ctl_target(v, "request.cookie.value:prefs", "request.header.value")
ok(has(v, "request.header.value:prefs"), "REQUEST_COOKIES:prefs leaves a header named prefs alone")
v = cookie_map()
remove_ctl_target(v, "request.arg.value:prefs", "request.cookie.value")
ok(count(v) == count(cookie_map()), "ARGS:prefs leaves the cookie prefs (and its expansion) alone")

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

-- ctl:ruleEngine=On — the third position of the switch. Full coverage lives in
-- engine_on_control.lua; pinned here only as far as this file's readers go.
print("- ctl:ruleEngine=On overrides both the service setting and DetectionOnly")
rc = new_store()
apply_rule_controls(rc, { { detection_only = true } }, "999903")
apply_rule_controls(rc, { { engine_on = true } }, "999901")
ok(rc.engine_on == true and rc.detection_only == false and rc.engine_forced_by == "999901",
   "engine_on set, detection_only cleared, forcing rule recorded")
ok(rule_blocking_enabled(rc, false), "detection service → terminal actions fire anyway")
ok(not detection_only_active(rc), "fix_matched_parts sanitising is back too")
apply_rule_controls(rc, { { engine_off = true } }, "999905")
ok(rc.engine_on == false and rc.engine_forced_by == nil, "engine_off still wins over engine_on")

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
apply_rule_controls(rc, { { audit_request_body = true } }, "999910")
ok(rc.audit_request_body == true and rc.detection_only == true,
   "a later audit_request_body accumulates without disturbing the engine state")

-- ============================================================
print("")
print("- end to end: REQUEST_COOKIES|ARGS keeps matching on ARGS once the cookie collection is removed")
-- ============================================================
-- A request carrying the marker in a JSON cookie AND in a query argument, and
-- a rule looking at both collections. Removing the cookie collection must leave
-- the rule matching on the argument; removing both must silence it. Every
-- per-request path is driven through the real applier and the real matcher.
H.request.headers   = { Cookie = 'prefs={"k":"MARKER"}; sid=clean' }
H.request.raw_query = "q=MARKER&other=clean"

local function two_collection_rule(id, tags)
    return {
        id = id, phase = "access", tags = tags or { "OWASP_CRS", "attack-rce" },
        conditions = {
            { variables = { "request.cookie.value", "request.arg.value" },
              op = "contains", value = "MARKER", transform = {} },
        },
    }
end
local function matched_on(matches)
    local out = {}
    for _, m in ipairs(matches or {}) do out[#out + 1] = m.matched_on end
    table.sort(out)
    return table.concat(out, " ")
end
local function only_args(matches)
    if not matches or #matches == 0 then return false end
    for _, m in ipairs(matches) do
        if not tostring(m.matched_on):find("^request%.query%.") then return false end
    end
    return true
end

-- baseline: both collections carry the marker
H.reset()
local m, parts = H.match(two_collection_rule("900300"))
ok(m == true, "baseline: the rule matches")
ok(tostring(matched_on(parts)):find("request.cookie.json.prefs.value:k", 1, true) ~= nil,
   "baseline: the cookie's JSON-derived value is among the matches", matched_on(parts))

-- by id (ctl:ruleRemoveTargetById=900300;REQUEST_COOKIES)
H.reset()
engine.__apply_rule_controls_inline({
    { remove_target_from_rule_by_id = { rule_id = "900300", target = "request.cookie.value" } },
}, "999001")
m, parts = H.match(two_collection_rule("900300"))
ok(m == true, "by id: still matches", matched_on(parts))
ok(only_args(parts), "by id: every match is on ARGS (query), none on the cookie", matched_on(parts))
H.reset()
engine.__apply_rule_controls_inline({
    { remove_target_from_rule_by_id = { rule_id = "900300", target = "request.cookie.value" } },
    { remove_target_from_rule_by_id = { rule_id = "900300", target = "request.arg.value" } },
}, "999001")
ok(H.match(two_collection_rule("900300")) == false, "by id: cookie AND args removed → no match")
H.reset()
engine.__apply_rule_controls_inline({
    { remove_target_from_rule_by_id = { rule_id = "900301", target = "request.cookie.value" } },
}, "999001")
m, parts = H.match(two_collection_rule("900300"))
ok(m == true and not only_args(parts), "by id: a different rule id leaves 900300 untouched")

-- by tag (ctl:ruleRemoveTargetByTag=attack-rce;REQUEST_COOKIES)
H.reset()
engine.__apply_rule_controls_inline({
    { remove_target_rule_by_tag = { tag = "attack-rce", name = "request.cookie.value" } },
}, "999002")
m, parts = H.match(two_collection_rule("900300"))
ok(m == true and only_args(parts), "by tag: tagged rule keeps matching, on ARGS only", matched_on(parts))
m, parts = H.match(two_collection_rule("900302", { "attack-xss" }))
ok(m == true and not only_args(parts), "by tag: a rule without the tag still matches on the cookie")

-- OWASP_CRS special case (all rules)
H.reset()
engine.__apply_rule_controls_inline({
    { remove_target_rule_by_tag = { tag = "OWASP_CRS", name = "request.cookie.value" } },
}, "999003")
m, parts = H.match(two_collection_rule("900300"))
ok(m == true and only_args(parts), "OWASP_CRS: the CRS-tagged rule matches on ARGS only")
m, parts = H.match(two_collection_rule("900303", { "custom" }))
ok(m == true and only_args(parts), "OWASP_CRS: a custom rule is covered too (all rules)")

-- per-name cookie exclusion end to end: the JSON-derived keys go with it
H.reset()
engine.__apply_rule_controls_inline({
    { remove_target_from_rule_by_id = { rule_id = "900300", target = "request.cookie.value:prefs" } },
}, "999004")
m, parts = H.match(two_collection_rule("900300"))
ok(m == true and only_args(parts), "REQUEST_COOKIES:prefs takes the JSON expansion of prefs out of the rule's view")

-- the compiled (stage-3) resolver path behaves the same
H.reset()
engine.__apply_rule_controls_inline({
    { remove_target_from_rule_by_id = { rule_id = "900300", target = "request.cookie.value" } },
}, "999005")
m, parts = H.match(H.attach_resolvers(two_collection_rule("900300")))
ok(m == true and only_args(parts), "compiled resolvers: cookie collection removed, ARGS still matches")

-- ============================================================
print("")
print("- copy-on-read: a removal in one rule never changes what the next rule sees (fast path on)")
-- ============================================================
-- Rule A has the cookie collection removed; rule B, evaluated right after on
-- the same request, has no exclusion and must still see the cookie. Before,
-- with the fast path on, a per-TAG target mutated the shared cache (the
-- `will_mutate` pre-check knew nothing about tags), and a removal on the FIRST
-- rule to resolve ARGS mutated the ARGS getter's own cache.
local function cookie_only_rule(id, tags)
    return {
        id = id, phase = "access", tags = tags or {},
        conditions = {
            { variables = { "request.cookie.value" }, op = "contains", value = "MARKER", transform = {} },
        },
    }
end
local function args_by_name_rule(id)
    return {
        id = id, phase = "access", tags = {},
        conditions = {
            { variables = { "request.arg.value:q" }, op = "contains", value = "MARKER", transform = {} },
        },
    }
end

-- A warm-up rule W resolves the variable first, so A reads it from the variable
-- cache (the fast path hands out the cached table itself): that is the shape in
-- which the old code leaked.
for _, mode in ipairs({ { name = "fast path ON", conf = { engine_fast_path = true } },
                        { name = "fast path OFF", conf = { engine_fast_path = false } } }) do
    -- by id
    H.reset()
    engine.__apply_rule_controls_inline({
        { remove_target_from_rule_by_id = { rule_id = "900400", target = "request.cookie.value" } },
    }, "999006")
    ok(H.match(cookie_only_rule("900399"), mode.conf) == true,  mode.name .. ": warm-up rule W sees the cookie")
    ok(H.match(cookie_only_rule("900400"), mode.conf) == false, mode.name .. ": rule A (excluded) does not match")
    ok(H.match(cookie_only_rule("900401"), mode.conf) == true,  mode.name .. ": rule B still sees the cookie (by-id removal did not leak)")
    ok(count(kong.ctx.plugin.ka_variable_cache["request.cookie.value"]) > 0,
       mode.name .. ": the variable cache still holds the cookie map")

    -- by tag — the path the old will_mutate pre-check missed
    H.reset()
    engine.__apply_rule_controls_inline({
        { remove_target_rule_by_tag = { tag = "attack-rce", name = "request.cookie.value" } },
    }, "999007")
    ok(H.match(cookie_only_rule("900398"), mode.conf) == true,  mode.name .. ": warm-up rule W sees the cookie")
    ok(H.match(cookie_only_rule("900402", { "attack-rce" }), mode.conf) == false, mode.name .. ": tagged rule A does not match")
    ok(H.match(cookie_only_rule("900403", { "attack-xss" }), mode.conf) == true,  mode.name .. ": rule B still sees the cookie (by-tag removal did not leak)")

    -- OWASP_CRS all-rules: B is excluded too, and the cache still holds the map
    H.reset()
    H.match(cookie_only_rule("900397"), mode.conf)  -- warm the cache before the control lands
    engine.__apply_rule_controls_inline({
        { remove_target_rule_by_tag = { tag = "OWASP_CRS", name = "request.cookie.value" } },
    }, "999008")
    ok(H.match(cookie_only_rule("900404"), mode.conf) == false, mode.name .. ": all-rules removal applies to A")
    ok(count(kong.ctx.plugin.ka_variable_cache["request.cookie.value"]) > 0,
       mode.name .. ": …without emptying the cached map")

    -- the ARGS getter's own cache: rule A is the FIRST to resolve ARGS and has a
    -- per-name removal; rule B then reads ARGS:q through the compiled by-name
    -- resolver, which iterates the getter's cached map directly.
    H.reset()
    engine.__apply_rule_controls_inline({
        { remove_target_from_rule_by_id = { rule_id = "900405", target = "request.arg.value:q" } },
    }, "999009")
    local a = two_collection_rule("900405", {})
    a.conditions[1].variables = { "request.arg.value" }
    ok(H.match(a, mode.conf) == false, mode.name .. ": rule A (ARGS:q excluded, only q carries the marker) does not match")
    ok(H.match(H.attach_resolvers(args_by_name_rule("900406")), mode.conf) == true,
       mode.name .. ": rule B still finds ARGS:q (the ARGS getter cache was not mutated)")
end

print(string.format("\n%d test(s) failed", fails))
os.exit(fails == 0 and 0 or 1)
