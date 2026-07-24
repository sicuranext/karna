-- ka-unittest/wordpress_target_exclusion.lua
--
-- Guards the ctl target-removal matcher `remove_ctl_target` in ka_engine.lua.
-- This is the fix for the CRS WordPress exclusion plugin false positive:
-- `ctl:ruleRemoveTargetById=942100;ARGS:pwd` maps to the target string
-- `request.arg.value:pwd`, but the body parser stores a urlencoded `pwd`
-- field under `request.body.urlencode.value:pwd` (query args under
-- `request.query.value:pwd`) — there is no flat `request.arg.value:pwd` key.
-- The old exact-key lookup (`values[target] = nil`) never matched, so the
-- exclusion was a no-op and rule 942100 kept blocking legit logins.
--
-- The fix matches by FIELD NAME (suffix), mirroring the rule-side ARGS
-- resolution, gated by namespace so `ARGS:pwd` can never strip a `pwd`
-- carried in a header or cookie. The security boundary IS that namespace
-- gate, so it gets deterministic coverage here.
--
-- SUT is replicated inline (same convention as default_block_response.lua)
-- so the test needs no kong/ngx globals. KEEP IN SYNC with
-- kong/plugins/karna/modules/ka_engine.lua:remove_ctl_target.
--
-- Run from repo root:
--   lua    ka-unittest/wordpress_target_exclusion.lua
--   luajit ka-unittest/wordpress_target_exclusion.lua

local string_find = string.find
local string_sub  = string.sub

-- ============================================================
-- SUT — copy from ka_engine.lua:remove_ctl_target
-- ============================================================
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

-- ============================================================
-- harness
-- ============================================================
local fails = 0
local function ok(cond, name)
    if cond then print("  ok  - " .. name)
    else print("  FAIL- " .. name); fails = fails + 1 end
end
local function has(values, k) return values[k] ~= nil end

-- ============================================================
-- THE FIX: ARGS:pwd exclusion strips the body-namespace key
-- ============================================================
print("- WordPress case: ARGS:pwd excludes a urlencoded body field")
local v = { ["request.body.urlencode.value:pwd"] = "' OR 1=1",
            ["request.body.urlencode.name:pwd"]  = "pwd" }
remove_ctl_target(v, "request.arg.value:pwd", "request.arg.value")
ok(not has(v, "request.body.urlencode.value:pwd"), "body value:pwd removed (rule 942100 no longer sees it)")
ok(not has(v, "request.body.urlencode.name:pwd"),  "body name:pwd removed too (mirrors rule-side :pwd$ match)")

print("- ARGS:pwd also strips a query-string arg of the same name")
v = { ["request.query.value:pwd"] = "x", ["request.query.value:user"] = "bob" }
remove_ctl_target(v, "request.arg.value:pwd", "request.arg.value")
ok(not has(v, "request.query.value:pwd"), "query value:pwd removed")
ok(has(v, "request.query.value:user"),    "other arg (user) untouched")

-- ============================================================
-- ANTI-BYPASS: the namespace gate
-- ============================================================
print("- ARGS:pwd does NOT strip a header named pwd (namespace gate)")
v = { ["request.header.value:pwd"] = "' OR 1=1" }
remove_ctl_target(v, "request.arg.value:pwd", "request.header.value")
ok(has(v, "request.header.value:pwd"), "header value:pwd survives — ARGS exclusion can't silence headers")

print("- ARGS:pwd does NOT strip a cookie named pwd (namespace gate)")
v = { ["request.cookie.value:pwd"] = "' OR 1=1" }
remove_ctl_target(v, "request.arg.value:pwd", "request.cookie.value")
ok(has(v, "request.cookie.value:pwd"), "cookie value:pwd survives")

-- ============================================================
-- BACK-COMPAT: concrete targets still match exactly
-- ============================================================
print("- concrete header exclusion still works (exact + gate)")
v = { ["request.header.value:referer"] = "http://evil" }
remove_ctl_target(v, "request.header.value:referer", "request.header.value")
ok(not has(v, "request.header.value:referer"), "header:referer removed")

print("- concrete query exclusion removes only the named arg")
v = { ["request.query.value:redirect_to"] = "//evil", ["request.query.value:log"] = "admin" }
remove_ctl_target(v, "request.query.value:redirect_to", "request.query.value")
ok(not has(v, "request.query.value:redirect_to"), "query:redirect_to removed")
ok(has(v, "request.query.value:log"),             "query:log untouched")

-- ============================================================
-- SUFFIX BOUNDARIES: name must match a whole field, not a substring
-- ============================================================
print("- suffix boundary: ARGS:pwd does not match 'password' or 'mypwd'")
v = { ["request.body.urlencode.value:password"] = "a",
      ["request.body.urlencode.value:mypwd"]    = "b",
      ["request.body.urlencode.value:pwd"]      = "c" }
remove_ctl_target(v, "request.arg.value:pwd", "request.arg.value")
ok(has(v, "request.body.urlencode.value:password"), "password NOT removed")
ok(has(v, "request.body.urlencode.value:mypwd"),    "mypwd NOT removed")
ok(not has(v, "request.body.urlencode.value:pwd"),  "pwd removed")

-- ============================================================
-- degenerate inputs don't crash
-- ============================================================
print("- degenerate inputs")
remove_ctl_target(nil, "request.arg.value:pwd", "request.arg.value")
ok(true, "nil values → no crash")
v = { ["request.arg.value"] = "x" }
remove_ctl_target(v, "request.arg.value", "request.arg.value")  -- whole-collection target, no :name
ok(true, "target without :name → no crash (exact-only)")

print(string.format("\n%d test(s) failed", fails))
os.exit(fails == 0 and 0 or 1)
