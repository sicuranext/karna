-- ka-unittest/cookie_empty_segment.lua
--
-- Guards the cookie variable resolver against an EMPTY cookie segment, an
-- availability bug any unauthenticated client could trigger with one malformed
-- request header.
--
-- `__get_values_request_cookie` splits the Cookie header on `;` with a helper
-- that iterates `(input .. ";")`, so a header already ending in `;` yields a
-- trailing EMPTY element; a leading `;` and a doubled `;;` yield one too. The
-- per-segment parse is `string_match(pair, "([^=]+)=?(.*)")`, and `[^=]+`
-- requires at least one character, so it returned NIL for those elements — and
-- the very next line called string_gsub on that nil:
--
--     ka_engine.lua:<n>: bad argument #1 to 'string_gsub' (string expected, got nil)
--
-- Nothing between there and handler.lua:access pcalls loop_rules, so the error
-- left the access phase and the proxy answered HTTP 500. One CRS rule targeting
-- REQUEST_COOKIES on the service is enough to reach the resolver, so every
-- request carrying `Cookie: a=1;` 500'd.
--
-- A whitespace-only segment ("a=1; ;b=2", "a=1; ") did not crash but trimmed to
-- an empty cookie name and inserted a junk `request.cookie.name:` /
-- `request.cookie.value:` pair under an EMPTY selector — a key no rule can
-- address, walked by every collection scan.
--
-- What is pinned here, all driven through the REAL resolver:
--   1. every crashing shape resolves without error;
--   2. each resolves to exactly the cookies it should, and to nothing else;
--   3. no entry with an empty selector is ever produced;
--   4. the shapes that already worked keep resolving identically;
--   5. a key-only cookie ("foo") stays a name-only cookie, and surrounding
--      whitespace is still trimmed off the name;
--   6. `<whitespace>=<value>` — the one empty-name shape that still carries
--      attacker bytes — stays INSPECTABLE under the synthetic
--      `request.cookie.value:__ka_unnamed_cookie_<n>` selector, so skipping
--      empty names did not open an inspection gap;
--   7. a REQUEST_COOKIES rule still matches through a header that ends with
--      `;` plus whitespace (the resolver is reached, not merely non-throwing).
--
-- Fixtures are synthetic.
--
-- Run from repo root:
--   lua    ka-unittest/cookie_empty_segment.lua
--   luajit ka-unittest/cookie_empty_segment.lua

local H = dofile("./ka-unittest/_engine_harness.lua")
local engine = H.engine

local fails = 0
local function ok(cond, name, detail)
    if cond then print("  ok  - " .. name)
    else print("  FAIL- " .. name .. (detail and ("  (" .. tostring(detail) .. ")") or "")); fails = fails + 1 end
end

-- resolve one Cookie header through the real resolver; never lets an error
-- escape, so a regression shows up as a FAIL line and not as a dead run
local function resolve(cookie_header)
    H.reset()
    H.request.headers = { Cookie = cookie_header }
    local called_ok, values = pcall(engine.__get_values_request_cookie, false)
    return called_ok, values
end

-- stable "k=v | k=v" rendering of the resolved map, for exact comparison
local function render(values)
    local parts = {}
    for k, v in pairs(values) do parts[#parts + 1] = k .. "=" .. tostring(v) end
    table.sort(parts)
    return table.concat(parts, " | ")
end

local function empty_selector_keys(values)
    local out = {}
    for k in pairs(values) do
        if k == "request.cookie.name:" or k == "request.cookie.value:"
           or k:match("^request%.cookie%.[a-z]+:%s*$") then
            out[#out + 1] = k
        end
    end
    table.sort(out)
    return table.concat(out, " ")
end

-- ---------------------------------------------------------------------------
-- 1/2/3. the shapes that used to raise, and the ones that used to leave junk
-- ---------------------------------------------------------------------------
-- `crashed` records the pre-fix behaviour, so the table doubles as the bug report
local cases = {
    { header = "a=1;",      crashed = true,  want = "request.cookie.name:a=a | request.cookie.value:a=1" },
    { header = ";a=1",      crashed = true,  want = "request.cookie.name:a=a | request.cookie.value:a=1" },
    { header = "a=1;;b=2",  crashed = true,  want = "request.cookie.name:a=a | request.cookie.name:b=b | " ..
                                                    "request.cookie.value:a=1 | request.cookie.value:b=2" },
    { header = ";",         crashed = true,  want = "" },
    { header = ";;",        crashed = true,  want = "" },
    -- these never crashed, but inserted an empty-selector pair
    { header = "a=1; ;b=2", crashed = false, want = "request.cookie.name:a=a | request.cookie.name:b=b | " ..
                                                    "request.cookie.value:a=1 | request.cookie.value:b=2" },
    { header = "  ;a=1",    crashed = false, want = "request.cookie.name:a=a | request.cookie.value:a=1" },
    { header = "a=1; ",     crashed = false, want = "request.cookie.name:a=a | request.cookie.value:a=1" },
    -- 4/5. the shapes that already resolved correctly must not move
    { header = "a=1; b=2",  crashed = false, want = "request.cookie.name:a=a | request.cookie.name:b=b | " ..
                                                    "request.cookie.value:a=1 | request.cookie.value:b=2" },
    { header = "foo",       crashed = false, want = "request.cookie.name:foo=foo | request.cookie.value:foo=" },
    { header = "  sid  =abc",
                            crashed = false, want = "request.cookie.name:sid=sid | request.cookie.value:sid=abc" },
}

for _, c in ipairs(cases) do
    local label = string.format("%q", c.header)
    local called_ok, values = resolve(c.header)
    ok(called_ok, "resolves without error: " .. label .. (c.crashed and "  [used to 500]" or ""),
       not called_ok and values or nil)
    if called_ok then
        ok(render(values) == c.want, "resolves to exactly the expected cookies: " .. label, render(values))
        ok(empty_selector_keys(values) == "", "no empty-selector entry: " .. label, empty_selector_keys(values))
    else
        fails = fails + 2
    end
end

-- a cookie-heavy header that ends with `;` followed by whitespace
local heavy = "sid=abcdef; theme=dark; lang=en-GB; tz=Europe%2FRome; consent=1; _ga=GA1.2.3.4;   "
local called_ok, values = resolve(heavy)
ok(called_ok, "resolves without error: cookie-heavy header ending in `;` + whitespace",
   not called_ok and values or nil)
if called_ok then
    ok(render(values) ==
       "request.cookie.name:_ga=_ga | request.cookie.name:consent=consent | " ..
       "request.cookie.name:lang=lang | request.cookie.name:sid=sid | " ..
       "request.cookie.name:theme=theme | request.cookie.name:tz=tz | " ..
       "request.cookie.value:_ga=GA1.2.3.4 | request.cookie.value:consent=1 | " ..
       "request.cookie.value:lang=en-GB | request.cookie.value:sid=abcdef | " ..
       "request.cookie.value:theme=dark | request.cookie.value:tz=Europe%2FRome",
       "cookie-heavy header resolves to all six cookies and nothing else", render(values))
    ok(empty_selector_keys(values) == "", "no empty-selector entry: cookie-heavy header")
end

-- ---------------------------------------------------------------------------
-- 6. skipping empty names must not drop attacker-controlled bytes
-- ---------------------------------------------------------------------------
-- `<whitespace>=<value>`: `[^=]+` matches the leading whitespace, so the name
-- trims to empty while the VALUE survives. Pre-fix this landed under the junk
-- empty selector and a REQUEST_COOKIES scan still walked it; dropping the
-- segment outright would have made this fix an inspection gap.
local called_ok2, unnamed = resolve("a=1; =' OR 1=1--")
ok(called_ok2, "resolves without error: whitespace-named cookie", not called_ok2 and unnamed or nil)
if called_ok2 then
    ok(unnamed["request.cookie.value:__ka_unnamed_cookie_1"] == "' OR 1=1--",
       "an empty-named cookie's value stays inspectable under a synthetic selector",
       unnamed["request.cookie.value:__ka_unnamed_cookie_1"])
    ok(unnamed["request.cookie.value:a"] == "1", "the named cookie alongside it is unaffected")
    ok(empty_selector_keys(unnamed) == "", "no empty-selector entry: whitespace-named cookie")
    -- no invented NAME: a name the client never sent must not reach
    -- REQUEST_COOKIES_NAMES rules
    local invented = nil
    for k in pairs(unnamed) do
        if k:find("^request%.cookie%.name:__ka_unnamed") then invented = k end
    end
    ok(invented == nil, "no synthetic cookie NAME is inserted", invented)
end
-- a whitespace-only segment carries nothing, so it produces nothing at all
local _, blank = resolve("a=1;   ;b=2")
local synthetic = nil
for k in pairs(blank) do if k:find("__ka_unnamed", 1, true) then synthetic = k end end
ok(synthetic == nil, "a whitespace-only segment produces no synthetic entry either", synthetic)

-- ---------------------------------------------------------------------------
-- 7. end to end: a REQUEST_COOKIES rule still matches through a trailing `;`
-- ---------------------------------------------------------------------------
-- Proves the resolver is actually reached and its map is what rules match on,
-- rather than the header merely failing to throw.
local function cookie_rule(needle)
    return {
        id = "900010", phase = "access", tags = {},
        conditions = {
            { variables = { "request.cookie.value" }, op = "contains",
              value = needle, transform = {} },
        },
    }
end

H.reset()
H.request.headers = { Cookie = "sid=abcdef; tracking=' OR 1=1--;  " }
ok(H.match(cookie_rule("OR 1=1")) == true,
   "REQUEST_COOKIES rule matches through a header ending in `;` + whitespace (dispatcher path)")
H.reset()
H.request.headers = { Cookie = "sid=abcdef; tracking=' OR 1=1--;  " }
ok(H.match(H.attach_resolvers(cookie_rule("OR 1=1"))) == true,
   "REQUEST_COOKIES rule matches through the same header (compiled resolver path)")
-- and the rule is not simply always-true
H.reset()
H.request.headers = { Cookie = "sid=abcdef;" }
ok(H.match(cookie_rule("OR 1=1")) == false, "the same rule does not match a clean cookie header")

print(string.format("\n%d test(s) failed", fails))
os.exit(fails == 0 and 0 or 1)
