-- ka-unittest/cookie_named_selector.lua
--
-- `request.cookie.value:<name>` and `request.cookie.name:<name>` as rule
-- CONDITION variables, access phase.
--
-- The selector was documented (docs/rules.html: "add a separate condition on
-- `request.cookie.value:sid`") and seclang emits it for `REQUEST_COOKIES:<n>`,
-- but neither the stage-3 compiled resolver nor the dispatcher had a branch for
-- it: only the bare `request.cookie.value` collection resolved. A named-cookie
-- condition therefore resolved to nothing on every request, and the engine
-- reads "resolved to nothing" as ABSENT. So:
--   * a negated `isSet` on a cookie fired on every request, cookie or not (a
--     "block unless the consent cookie is there" rule blocked real browsers);
--   * a positive `isSet` / `eq` / `rx` on a cookie never fired.
-- The bare `request.cookie.name` collection (REQUEST_COOKIES_NAMES) had the
-- same gap.
--
-- What is pinned here, through BOTH paths (the dispatcher, and the compiled
-- resolver that compile_rules attaches at init_worker):
--   1. cookie present: positive isSet / eq match, negated isSet does not;
--   2. cookie absent (no Cookie header; a Cookie header without that name):
--      negated isSet matches, positive isSet does not;
--   3. names are case-insensitive (the resolver stores them lowercased): a
--      mixed-case name in the request and a lowercase or mixed-case name in
--      the rule both resolve;
--   4. the same for `request.cookie.name:<name>`, and the bare
--      `request.cookie.name` collection yields names only;
--   5. a JSON cookie counts as present (its value lives under the derived
--      `request.cookie.json.<name>.*` keys, not the plain key);
--   6. a ctl:ruleRemoveTargetById on the cookie is an EXCLUSION, not absence:
--      the negated isSet must keep skipping;
--   7. `&REQUEST_COOKIES:<name>` (count:) counts 1 / 0;
--   8. the bare collection is unchanged;
--   9. ka_compile.is_known_condition_variable accepts the names the engine
--      resolves and rejects the ones it does not (they read as absent), and
--      compile_rules warns once per unknown name.
--
-- Run from repo root:
--   lua    ka-unittest/cookie_named_selector.lua
--   luajit ka-unittest/cookie_named_selector.lua

local H = dofile("./ka-unittest/_engine_harness.lua")
local engine, ka_compile = H.engine, H.ka_compile

local fails = 0
local function ok(cond, name, detail)
    if cond then print("  ok  - " .. name)
    else print("  FAIL- " .. name .. (detail and ("  (" .. tostring(detail) .. ")") or "")); fails = fails + 1 end
end

local function rule(id, variable, op, negated, value)
    return {
        id = id, phase = "access", tags = {},
        conditions = {
            { variables = { variable }, op = op, negated = negated,
              value = value, transform = {} },
        },
    }
end

-- run one rule through the dispatcher and through the compiled resolver
local function both(name, cookie_header, r_fn, expected, setup)
    for _, path in ipairs({ "dispatcher", "compiled" }) do
        H.request.headers = cookie_header and { Cookie = cookie_header } or {}
        local rc = H.reset()
        if setup then setup(rc) end
        local r = r_fn()
        if path == "compiled" then H.attach_resolvers(r) end
        local got = H.match(r)
        ok(got == expected, name .. " [" .. path .. "]", "got " .. tostring(got))
    end
end

local JAR = "a=1; ConsentCookie=yes; viewed_policy=yes"

-- ===========================================================================
print("- 0. the compiled resolver claims the named selectors")
-- ===========================================================================
ok(type(ka_compile.compile_variable_resolver("request.cookie.value:consentcookie")) == "function",
   "request.cookie.value:<n> is precompiled")
ok(type(ka_compile.compile_variable_resolver("request.cookie.name:consentcookie")) == "function",
   "request.cookie.name:<n> is precompiled")
ok(type(ka_compile.compile_variable_resolver("request.cookie.name")) == "function",
   "request.cookie.name is precompiled")

-- ===========================================================================
print("- 1. cookie present")
-- ===========================================================================
both("negated isSet on a present cookie does NOT match", JAR,
     function() return rule("900100", "request.cookie.value:consentcookie", "isSet", true) end, false)
both("positive isSet on a present cookie matches", JAR,
     function() return rule("900101", "request.cookie.value:consentcookie", "isSet", false) end, true)
both("eq yes on a present cookie matches", JAR,
     function() return rule("900102", "request.cookie.value:consentcookie", "eq", false, "yes") end, true)
both("eq on another value does not match", JAR,
     function() return rule("900103", "request.cookie.value:consentcookie", "eq", false, "no") end, false)
both("legacy !isSet on a present cookie does NOT match", JAR,
     function() return rule("900104", "request.cookie.value:viewed_policy", "!isSet") end, false)

-- ===========================================================================
print("- 2. cookie absent")
-- ===========================================================================
both("no Cookie header: negated isSet matches", nil,
     function() return rule("900110", "request.cookie.value:consentcookie", "isSet", true) end, true)
both("no Cookie header: positive isSet does not match", nil,
     function() return rule("900111", "request.cookie.value:consentcookie", "isSet", false) end, false)
both("Cookie header without that name: negated isSet matches", "a=1; other=2",
     function() return rule("900112", "request.cookie.value:consentcookie", "isSet", true) end, true)
both("Cookie header without that name: positive isSet does not match", "a=1; other=2",
     function() return rule("900113", "request.cookie.value:consentcookie", "isSet", false) end, false)
both("a cookie whose name only CONTAINS the selector is not it", "xconsentcookie=1; consentcookiex=2",
     function() return rule("900114", "request.cookie.value:consentcookie", "isSet", false) end, false)

-- ===========================================================================
print("- 3. names are case-insensitive")
-- ===========================================================================
both("mixed-case name in the request, lowercase in the rule", "CONSENTCookie=yes",
     function() return rule("900120", "request.cookie.value:consentcookie", "eq", false, "yes") end, true)
both("mixed-case name in the rule too", "consentcookie=yes",
     function() return rule("900121", "request.cookie.value:ConsentCookie", "isSet", true) end, false)

-- ===========================================================================
print("- 4. request.cookie.name:<name> and the bare name collection")
-- ===========================================================================
both("name selector, present: negated isSet does not match", JAR,
     function() return rule("900130", "request.cookie.name:consentcookie", "isSet", true) end, false)
both("name selector, present: eq on the ORIGINAL-case name matches", JAR,
     function() return rule("900131", "request.cookie.name:consentcookie", "eq", false, "ConsentCookie") end, true)
both("name selector, absent: negated isSet matches", "a=1",
     function() return rule("900132", "request.cookie.name:consentcookie", "isSet", true) end, true)
both("bare name collection sees a name", JAR,
     function() return rule("900133", "request.cookie.name", "eq", false, "viewed_policy") end, true)
both("bare name collection does not see values", "k=secretvalue",
     function() return rule("900134", "request.cookie.name", "eq", false, "secretvalue") end, false)
both("value selector does not see the name entry", "k=v",
     function() return rule("900135", "request.cookie.value:k", "eq", false, "k") end, false)

-- ===========================================================================
print("- 5. a JSON cookie is present")
-- ===========================================================================
both("JSON cookie: negated isSet does not match", 'prefs={"a":"x"}; sid=1',
     function() return rule("900140", "request.cookie.value:prefs", "isSet", true) end, false)
both("JSON cookie: its flattened value is inspected", 'prefs={"a":"payload"}; sid=1',
     function() return rule("900141", "request.cookie.value:prefs", "contains", false, "payload") end, true)
both("JSON cookie of ANOTHER name is not picked up", 'prefsx={"a":"payload"}',
     function() return rule("900142", "request.cookie.value:prefs", "isSet", false) end, false)

-- ===========================================================================
print("- 6. a ctl target exclusion is not absence")
-- ===========================================================================
both("baseline, absent cookie and no exclusion: negated isSet fires", "a=1",
     function() return rule("900150", "request.cookie.value:consentcookie", "isSet", true) end, true)
both("ruleRemoveTargetById on a PRESENT cookie: negated isSet does not fire", JAR,
     function() return rule("900151", "request.cookie.value:consentcookie", "isSet", true) end, false,
     function(rc) rc.ids_targets["900151"] = { "request.cookie.value:consentcookie" } end)
both("ruleRemoveTargetById on a PRESENT cookie: positive eq is silenced", JAR,
     function() return rule("900152", "request.cookie.value:consentcookie", "eq", false, "yes") end, false,
     function(rc) rc.ids_targets["900152"] = { "request.cookie.value:consentcookie" } end)

-- ===========================================================================
print("- 7. &REQUEST_COOKIES:<name>")
-- ===========================================================================
both("count of a present cookie is 1", JAR,
     function() return rule("900160", "count:request.cookie.value:consentcookie", "eq", false, "1") end, true)
both("count of an absent cookie is 0", "a=1",
     function() return rule("900161", "count:request.cookie.value:consentcookie", "eq", false, "0") end, true)

-- ===========================================================================
print("- 8. the bare collection is unchanged")
-- ===========================================================================
H.request.headers = { Cookie = JAR }
H.reset()
local all = engine.__get_values_request_cookie(false)
ok(all["request.cookie.value:consentcookie"] == "yes" and all["request.cookie.name:consentcookie"] == "ConsentCookie",
   "REQUEST_COOKIES still carries name and value keys")
both("REQUEST_COOKIES still matches a cookie NAME (unchanged)", JAR,
     function() return rule("900170", "request.cookie.value", "eq", false, "viewed_policy") end, true)

-- ===========================================================================
print("- 9. unknown condition variables are reported at load")
-- ===========================================================================
local known = ka_compile.is_known_condition_variable
for _, v in ipairs({
    "request.cookie.value", "request.cookie.name", "request.cookie.value:sid",
    "request.cookie.name:sid", "request.header.value:referer", "request.arg.value:id",
    "request.query.value:q", "request.path", "request.body.json.value:a",
    "response.status", "tx:score", "group:1", "matched.value", "redis.ban:%{remote_addr}",
    "count:request.cookie.value:sid", "count:request.header.value:host",
}) do
    ok(known(v) == true, "known: " .. v)
end
for _, v in ipairs({
    "request.cookie.vaule:sid", "request.cookies.value:sid", "geoip.country_code",
    "var:paranoia_level", "request.header.name", "request.header.referer.path",
    "request.forwarded_host", "request.file:upload", "count:request.arg.value:action",
    "group:x", "", "REQUEST_COOKIES:sid",
}) do
    ok(known(v) == false, "unknown: " .. (v == "" and "<empty>" or v))
end

local warned = {}
local saved_warn = kong.log.warn
kong.log.warn = function(...) warned[#warned + 1] = table.concat({ ... }) end
ka_compile.compile_rules({
    rule("900180", "request.cookie.vaule:sid", "isSet", true),
    rule("900181", "request.cookie.vaule:sid", "isSet", false),
    rule("900182", "request.cookie.value:sid", "isSet", true),
}, nil)
kong.log.warn = saved_warn
ok(#warned == 1, "one warning for the unknown name, none for the known one", #warned)
ok(warned[1] and warned[1]:find("request.cookie.vaule:sid", 1, true) ~= nil,
   "the warning names the variable", warned[1])

print(string.format("\n%d test(s) failed", fails))
os.exit(fails == 0 and 0 or 1)
