-- Smoke test for the ka_ac FFI binding.
--
-- Run inside the karna container (LuaJIT/FFI required), e.g.:
--   docker exec bench-karna resty /usr/local/kong/custom-plugins/karna/tests/ka_ac_smoke.lua
-- The dev image installs the .so at /usr/local/lib/libka_ac.so; alternatively
-- set KARNA_LIBKA_AC_SO to point at a custom build.
--
-- Mirrors the C-level smoke tests in src/libka_ac/test_ka_ac.c, but exercises
-- the Lua wrapper end-to-end.

package.path = '/usr/local/kong/custom-plugins/karna/kong/plugins/karna/?.lua;' .. package.path

local ka_ac = require "modules.ka_ac"

if not ka_ac.available() then
    error("libka_ac.so not loadable — check KARNA_LIBKA_AC_SO / /usr/local/lib/libka_ac.so")
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
-- test 1: basic matching, case-insensitive
------------------------------------------------------------------
do
    local h, err = ka_ac.build({ "foo", "bar", "baz" })
    if not h then error("build failed: " .. tostring(err)) end
    eq("n_patterns", h.n_patterns, 3)

    local bm = ka_ac.new_bitmap(h)
    ka_ac.scan(h, "hello FOO world", bm)
    eq("basic foo",      ka_ac.bit_test(bm, 0), true)
    eq("basic !bar",     ka_ac.bit_test(bm, 1), false)
    eq("basic !baz",     ka_ac.bit_test(bm, 2), false)

    ka_ac.bitmap_clear(bm, h)
    ka_ac.scan(h, "BarBaz Foo", bm)
    eq("triple foo", ka_ac.bit_test(bm, 0), true)
    eq("triple bar", ka_ac.bit_test(bm, 1), true)
    eq("triple baz", ka_ac.bit_test(bm, 2), true)

    ka_ac.bitmap_clear(bm, h)
    ka_ac.scan(h, "nothing matches here", bm)
    eq("empty foo", ka_ac.bit_test(bm, 0), false)
    eq("empty bar", ka_ac.bit_test(bm, 1), false)
    eq("empty baz", ka_ac.bit_test(bm, 2), false)
end

------------------------------------------------------------------
-- test 2: classic AC overlap (ushers → he/she/hers)
------------------------------------------------------------------
do
    local h = assert(ka_ac.build({ "he", "she", "his", "hers" }))
    local bm = ka_ac.new_bitmap(h)
    ka_ac.scan(h, "ushers", bm)
    eq("ushers/he",   ka_ac.bit_test(bm, 0), true)
    eq("ushers/she",  ka_ac.bit_test(bm, 1), true)
    eq("ushers/!his", ka_ac.bit_test(bm, 2), false)
    eq("ushers/hers", ka_ac.bit_test(bm, 3), true)
end

------------------------------------------------------------------
-- test 3: realistic CRS-style sqli literal
------------------------------------------------------------------
do
    local h = assert(ka_ac.build({ "union", "select", "passwd", "<script", "alert(" }))
    local bm = ka_ac.new_bitmap(h)
    ka_ac.scan(h, "1' UNION SELECT password FROM users--", bm)
    eq("sqli/union",  ka_ac.bit_test(bm, 0), true)
    eq("sqli/select", ka_ac.bit_test(bm, 1), true)
    eq("sqli/!passwd",ka_ac.bit_test(bm, 2), false)   -- 'password' contains 'passwo', not 'passwd'
    eq("sqli/!<script",ka_ac.bit_test(bm, 3), false)
    eq("sqli/!alert(",ka_ac.bit_test(bm, 4), false)

    ka_ac.bitmap_clear(bm, h)
    ka_ac.scan(h, "<SCRIPT>alert(document.cookie)</SCRIPT>", bm)
    eq("xss/!union",    ka_ac.bit_test(bm, 0), false)
    eq("xss/!select",   ka_ac.bit_test(bm, 1), false)
    eq("xss/<script",   ka_ac.bit_test(bm, 3), true)
    eq("xss/alert(",    ka_ac.bit_test(bm, 4), true)
end

------------------------------------------------------------------
-- test 4: info / memory
------------------------------------------------------------------
do
    local h = assert(ka_ac.build({ "a", "ab", "abc" }))
    local info = ka_ac.info(h)
    eq("info n_patterns", info.n_patterns, 3)
    if info.memory_bytes <= 0 then
        io.write("FAIL info.memory_bytes > 0: got " .. info.memory_bytes .. "\n")
        fails = fails + 1
    else
        io.write("OK   info.memory_bytes = " .. info.memory_bytes .. "\n")
    end
end

------------------------------------------------------------------
-- summary
------------------------------------------------------------------
if fails > 0 then
    io.write("\n" .. fails .. " TEST(S) FAILED\n")
    os.exit(1)
end
io.write("\nALL SMOKE TESTS PASSED\n")
