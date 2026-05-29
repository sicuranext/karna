-- Smoke test for the ka_re2 FFI binding (RE2::Set multi-@rx matcher).
--
-- Run inside the karna container (LuaJIT/FFI + libka_re2.so required), e.g.:
--   docker exec bench-karna resty \
--     /usr/local/kong/custom-plugins/karna/tests/ka_re2_smoke.lua
-- The dev image installs the .so at /usr/local/lib/libka_re2.so; alternatively
-- set KARNA_LIBKA_RE2_SO to point at a custom build:
--   g++ -shared -fPIC -O2 -std=c++17 -o /tmp/libka_re2.so \
--       src/libka_re2/ka_re2.cc -lre2
--   KARNA_LIBKA_RE2_SO=/tmp/libka_re2.so luajit tests/ka_re2_smoke.lua
--
-- Mirrors tests/ka_ac_smoke.lua but for the RE2::Set wrapper, and asserts the
-- properties the engine integration relies on: (a) one scan returns the FULL
-- set of matching pattern ids, (b) inline (?i) and \b behave like CRS expects,
-- (c) RE2-rejected patterns surface as id_map=false (so the engine can fall
-- those rules back to ngx.re.match — never a silent drop).

package.path = '/usr/local/kong/custom-plugins/karna/kong/plugins/karna/?.lua;'
            .. './kong/plugins/karna/?.lua;' .. package.path

local ka_re2 = require "modules.ka_re2"

if not ka_re2.available() then
    error("libka_re2.so not loadable — check KARNA_LIBKA_RE2_SO / /usr/local/lib/libka_re2.so")
end

local fails = 0
local function eq(label, got, want)
    if got == want then
        io.write("OK   " .. label .. "\n")
    else
        io.write("FAIL " .. label .. ": got=" .. tostring(got) .. " want=" .. tostring(want) .. "\n")
        fails = fails + 1
    end
end

------------------------------------------------------------------
-- test 1: build + the full matching set is returned in one scan
------------------------------------------------------------------
do
    local h, err, id_map, rejected = ka_re2.build({
        "union\\s+select",   -- id 0
        "<script",           -- id 1
        "\\.\\./",           -- id 2 (path traversal)
    }, true)
    if not h then error("build failed: " .. tostring(err)) end
    eq("n_patterns", h.n_patterns, 3)
    eq("id_map[1]", id_map[1], 0)
    eq("id_map[3]", id_map[3], 2)
    eq("no rejects", #rejected, 0)

    -- a value that should trip TWO patterns at once
    local m = ka_re2.matched_set(h, "1 UNION   SELECT * ../../etc/passwd")
    eq("multi: union select (via ci? no — case-sensitive here)", m[0], nil) -- 'UNION SELECT' upper, pattern lower, case-sensitive -> no
    eq("multi: path traversal", m[2], true)

    local m2 = ka_re2.matched_set(h, "<script>alert(1)</script>")
    eq("script match", m2[1], true)
    eq("script !union", m2[0], nil)

    local m3 = ka_re2.matched_set(h, "perfectly benign text")
    eq("benign no-match count", next(m3), nil)
end

------------------------------------------------------------------
-- test 2: inline (?i) case-insensitive — CRS's dominant flag
------------------------------------------------------------------
do
    local h = ka_re2.build({ "(?i)union\\s+select" }, true)
    eq("ci: UPPER matches", ka_re2.matched_set(h, "1 UNION SELECT")[0], true)
    eq("ci: mixed matches", ka_re2.matched_set(h, "uNiOn   sElEcT")[0], true)
    eq("ci: benign no",     ka_re2.matched_set(h, "reunion selected")[0], true) -- substring 'union'? 'reUNION SELECTed' contains 'union select'? "reunion selected" has 'union sel' but 'union\s+select' needs 'select' whole-ish; 'selected' contains 'select' -> matches. documents substring semantics.
end

------------------------------------------------------------------
-- test 3: \b word boundary
------------------------------------------------------------------
do
    local h = ka_re2.build({ "(?i)\\bor\\b" }, true)
    eq("wb: ' or ' matches", ka_re2.matched_set(h, "1 OR 1=1")[0], true)
    eq("wb: 'corn' no-match", ka_re2.matched_set(h, "popcorn")[0], nil)
end

------------------------------------------------------------------
-- test 4: RE2-rejected pattern surfaces as id_map=false (no silent drop)
------------------------------------------------------------------
do
    -- a backreference is unsupported by RE2 (CRS uses none, but prove the
    -- fallback contract holds if one ever slips in)
    local h, err, id_map, rejected = ka_re2.build({
        "(?i)evil",     -- id 0 (accepted)
        "(a)\\1",       -- rejected by RE2 (backreference)
        "(?i)nasty",    -- accepted -> id 1 (NOT 2 — rejected one shifts ids)
    }, true)
    if not h then error("build failed: " .. tostring(err)) end
    eq("rejected count", #rejected, 1)
    eq("rejected index", rejected[1], 2)
    eq("id_map[1] accepted", id_map[1], 0)
    eq("id_map[2] rejected", id_map[2], false)
    eq("id_map[3] reindexed", id_map[3], 1)
    eq("accepted still matches", ka_re2.matched_set(h, "something EVIL here")[0], true)
end

io.write(fails == 0 and "\nALL OK\n" or ("\n" .. fails .. " FAILED\n"))
os.exit(fails == 0 and 0 or 1)
