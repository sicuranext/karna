-- ka-unittest/cookie_b64_resolver.lua
--
-- Guards the cookie variable resolver against the base64 pass being switched
-- on behind the plugin's back.
--
-- `__get_values_request_cookie(try_b64)` is a self-less function (dot-call,
-- like the other request getters). Two call sites used the colon form —
-- the compiled `request.cookie.value` resolver in ka_compile.lua (the one the
-- fast path actually runs for every REQUEST_COOKIES rule) and the
-- `count:request.cookie.value` probe (`&REQUEST_COOKIES`) — so the ENGINE
-- TABLE arrived in `try_b64`. A table is truthy: every JSON cookie was
-- flattened with the base64 pass on, whatever `try_bas64decode_if_possible`
-- (schema default `false`) said. A consent / preference cookie whose short
-- opaque string values are valid base64 grew
-- `request.cookie.json.<name>.value:<key>_ka_b64_decoded` entries holding
-- binary garbage, and CRS rules targeting REQUEST_COOKIES matched the garbage
-- (932340 blocking ordinary browsers in production).
--
-- What is pinned here, with a synthetic fixture:
--   1. the compiled resolver hands the raw resolver a literal `false`
--      (checked through ka_compile.compile_variable_resolver with a recording
--      engine, so a colon call — which passes the engine table — fails);
--   2. the real resolver with the flag OFF yields no `_ka_b64_decoded` key,
--      and with the flag ON yields them (the fixture is load-bearing);
--   3. the compiled resolver on the real engine yields none either;
--   4. a stray truthy non-boolean (the engine table itself) is treated as OFF —
--      the resolver normalises `try_b64` to a strict boolean;
--   5. the `count:request.cookie.value` probe counts the plain map, not the
--      base64-inflated one.
--
-- The rule-matching path passes a literal `false` for cookies, as it does for
-- ARGS / query / body: `try_bas64decode_if_possible` does not reach the
-- request-phase resolvers by design (see the comment on the resolver).
--
-- Run from repo root:
--   lua    ka-unittest/cookie_b64_resolver.lua
--   luajit ka-unittest/cookie_b64_resolver.lua

local H = dofile("./ka-unittest/_engine_harness.lua")
local engine, ka_compile = H.engine, H.ka_compile

local fails = 0
local function ok(cond, name, detail)
    if cond then print("  ok  - " .. name)
    else print("  FAIL- " .. name .. (detail and ("  (" .. tostring(detail) .. ")") or "")); fails = fails + 1 end
end

local function count_keys(t)
    local n = 0
    if type(t) == "table" then for _ in pairs(t) do n = n + 1 end end
    return n
end
local function b64_keys(t)
    local out = {}
    if type(t) == "table" then
        for k in pairs(t) do
            if k:find("_ka_b64_decoded", 1, true) then out[#out + 1] = k end
        end
    end
    table.sort(out)
    return out
end

-- ---------------------------------------------------------------------------
-- fixture: a JSON preference cookie whose string values are valid base64
-- ("YWJj" = "abc", "ZGVm" = "def"), next to a plain cookie
-- ---------------------------------------------------------------------------
H.request.headers = { Cookie = 'prefs={"1":"YWJj","2":"ZGVm"}; sid=plainvalue' }
H.reset()

-- ===========================================================================
print("- 1. the compiled resolver calls the raw resolver with a literal false")
-- ===========================================================================
local resolver = ka_compile.compile_variable_resolver("request.cookie.value")
ok(type(resolver) == "function", "ka_compile precompiles request.cookie.value")

local recorded_n, recorded_arg = nil, "never called"
local recording_engine = {}
recording_engine.__get_values_request_cookie = function(...)
    recorded_n = select("#", ...)
    recorded_arg = (...)
    return {}, nil
end
resolver(recording_engine, { id = "900000" })
ok(recorded_n == 1, "exactly one argument reaches the resolver (a colon call passes two)", recorded_n)
ok(recorded_arg == false, "that argument is the boolean false, not the engine table",
   type(recorded_arg))

-- ===========================================================================
print("- 2. the real resolver: flag off → no base64 keys; flag on → base64 keys")
-- ===========================================================================
local plain = engine.__get_values_request_cookie(false)
ok(plain["request.cookie.json.prefs.value:1"] == "YWJj", "JSON cookie flattened (value:1)")
ok(plain["request.cookie.json.prefs.value:2"] == "ZGVm", "JSON cookie flattened (value:2)")
ok(plain["request.cookie.value:sid"] == "plainvalue",    "plain cookie kept as-is")
ok(#b64_keys(plain) == 0, "flag off → no *_ka_b64_decoded key", table.concat(b64_keys(plain), ","))

local decoded = engine.__get_values_request_cookie(true)
ok(decoded["request.cookie.json.prefs.value:1_ka_b64_decoded"] == "abc",
   "flag on → derived key value:1_ka_b64_decoded = abc",
   decoded["request.cookie.json.prefs.value:1_ka_b64_decoded"])
ok(decoded["request.cookie.json.prefs.value:2_ka_b64_decoded"] == "def",
   "flag on → derived key value:2_ka_b64_decoded = def")
ok(count_keys(decoded) > count_keys(plain),
   "fixture is load-bearing: the base64 pass adds keys", count_keys(decoded) .. " vs " .. count_keys(plain))

-- ===========================================================================
print("- 3. the compiled resolver on the real engine yields no base64 key")
-- ===========================================================================
local compiled_values = resolver(engine, { id = "900000" })
ok(type(compiled_values) == "table" and compiled_values["request.cookie.json.prefs.value:1"] == "YWJj",
   "compiled resolver returns the flattened cookie map")
ok(#b64_keys(compiled_values) == 0, "compiled resolver → no *_ka_b64_decoded key (the regression)",
   table.concat(b64_keys(compiled_values), ","))
ok(count_keys(compiled_values) == count_keys(plain), "compiled map == raw flag-off map")

-- ===========================================================================
print("- 4. a truthy non-boolean is treated as OFF (strict boolean)")
-- ===========================================================================
local colon_shaped = engine.__get_values_request_cookie(engine)  -- what a colon call passes
ok(#b64_keys(colon_shaped) == 0, "engine table in try_b64 → no base64 pass")
local string_shaped = engine.__get_values_request_cookie("true")
ok(#b64_keys(string_shaped) == 0, "the string \"true\" in try_b64 → no base64 pass")

-- ===========================================================================
print("- 5. the count:request.cookie.value probe counts the plain map")
-- ===========================================================================
local n_plain, n_b64 = count_keys(plain), count_keys(decoded)
local function count_rule(expected)
    return {
        id = "900001", phase = "access", tags = {},
        conditions = {
            { variables = { "count:request.cookie.value" }, op = "eq",
              value = tostring(expected), transform = {} },
        },
    }
end
H.reset()
local matched_plain = H.match(count_rule(n_plain))
ok(matched_plain == true, "&REQUEST_COOKIES @eq <plain count> matches", n_plain)
H.reset()
local matched_b64 = H.match(count_rule(n_b64))
ok(matched_b64 == false, "&REQUEST_COOKIES @eq <base64-inflated count> does NOT match", n_b64)

-- A rule on REQUEST_COOKIES must not see the DECODED value ("abc" is what
-- "YWJj" decodes to): with the pass off it is never in the map. Both the
-- dispatcher path and the compiled (stage-3) path are exercised.
local function decoded_rule()
    return {
        id = "900002", phase = "access", tags = {},
        conditions = {
            { variables = { "request.cookie.value" }, op = "contains",
              value = "abc", transform = {} },
        },
    }
end
H.reset()
ok(H.match(decoded_rule()) == false, "rule on REQUEST_COOKIES does not match the base64-decoded value (dispatcher path)")
H.reset()
ok(H.match(H.attach_resolvers(decoded_rule())) == false,
   "rule on REQUEST_COOKIES does not match the base64-decoded value (compiled resolver path)")
-- and the encoded value IS visible, so the rule is not simply blind
H.reset()
local visible = decoded_rule(); visible.conditions[1].value = "YWJj"
ok(H.match(visible) == true, "the cookie's actual value is inspected")

print(string.format("\n%d test(s) failed", fails))
os.exit(fails == 0 and 0 or 1)
