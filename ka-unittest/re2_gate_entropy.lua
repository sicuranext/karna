-- ka-unittest/re2_gate_entropy.lua
--
-- The RE2 gate pre-pass (ka_re2_gate.scan) on high-entropy input.
--
-- The combined RE2::Set over the ~200 CRS PL1 @rx patterns builds its DFA
-- lazily. Ordinary text reuses the states it already has; random bytes or
-- random printable text reach a new state on almost every byte, and building
-- one costs tens of microseconds. The fix sends long values, and every value
-- after a small per-request budget, to one Set per pattern instead.
--
-- Checked here, with the real CRS patterns and the real libka_re2.so:
--   1. the sharded path reports exactly the pattern ids the combined Set
--      reports (gating decisions unchanged), on short, long, attack, random
--      and many-value inputs;
--   2. the high-entropy inputs finish within a bound the old code missed by
--      one to two orders of magnitude;
--   3. a shard that failed to build reports its pattern as matched (the rule
--      runs), never as a silent skip.
--
-- Needs LuaJIT + libka_re2.so + the CRS rules (KARNA_CRS_PATH, default
-- /opt/coreruleset/rules/): run it inside the Kong image, from the repo root:
--   luajit ka-unittest/re2_gate_entropy.lua
-- Anywhere else (plain Lua in CI) it prints SKIP and exits 0.

package.path = "./kong/plugins/karna/modules/?.lua;" .. package.path

local function skip(why)
    print("SKIP re2_gate_entropy: " .. why)
    os.exit(0)
end

if not pcall(require, "ffi") then skip("no LuaJIT ffi") end

kong = {
    ctx = { plugin = {} },
    log = {
        err = function() end, warn = function() end, notice = function() end,
        debug = function() end, inspect = function() end,
    },
}

package.preload["kong.plugins.karna.ka_re2"]     = function() return dofile("./kong/plugins/karna/modules/ka_re2.lua") end
package.preload["kong.plugins.karna.ka_seclang"] = function() return dofile("./kong/plugins/karna/modules/seclang.lua") end
-- KA_RE2_GATE_FILE runs the test against another copy of the module (A/B).
package.preload["kong.plugins.karna.ka_re2_gate"] = function()
    local f = os.getenv("KA_RE2_GATE_FILE")
    return dofile((f and f ~= "") and f or "./kong/plugins/karna/modules/ka_re2_gate.lua")
end

-- The request under test: variable name -> { key = value }. The gate takes
-- its resolvers from ka_compile; here every variable resolves from REQ.
local REQ = {}
package.preload["kong.plugins.karna.ka_compile"] = function()
    return {
        compile_variable_resolver = function(v)
            return function() return REQ[v] or {} end
        end,
    }
end

local ka_re2 = require "kong.plugins.karna.ka_re2"
if not ka_re2.available() then skip("libka_re2.so not loadable") end

local ok_sl, seclang = pcall(require, "kong.plugins.karna.ka_seclang")
if not ok_sl then skip("seclang did not load: " .. tostring(seclang)) end
local raw = seclang.collect_crs_conf_files()
if next(raw) == nil then skip("no CRS rules at " .. seclang.crs_path) end

local gate_mod = require "kong.plugins.karna.ka_re2_gate"

-- PL1 access-phase rules, the set the gate is built from in production.
-- seclang.parse accumulates into the module's rule table and returns it.
local parsed = {}
for _, content in pairs(raw) do parsed = seclang.parse(content) end
local rules = {}
for _, r in pairs(parsed) do
    if type(r) == "table" and r.phase == "access"
       and (tonumber(r.paranoia_level) or 1) <= 1 then
        rules[#rules + 1] = r
    end
end

local gate = gate_mod.build(rules)
if not gate then skip("gate build returned nil") end

local pass, fail = 0, 0
local function ok(cond, msg)
    if cond then pass = pass + 1; print("  ok   " .. msg)
    else fail = fail + 1; print("  FAIL " .. msg) end
end

print(string.format("gate: %d patterns, %d shards, %d specs",
      gate.n_patterns, gate.shards and #gate.shards or 0, #gate.specs))
ok(type(gate.shards) == "table" and #gate.shards == gate.gateable,
   "one shard per gateable pattern")

-- Every spec variable resolves from REQ; two transforms are enough to give
-- each value more than one distinct post-transform string.
local engine = {
    __apply_transformation = function(_, name, v)
        if name == "lowercase" then return v:lower() end
        if name == "removeWhitespace" then return (v:gsub("%s", "")) end
        return v
    end,
}

local function set_request(values)
    REQ = {}
    for _, sp in ipairs(gate.specs) do REQ[sp.variable] = values end
    kong.ctx.plugin = {}
end

local function run_sharded()
    kong.ctx.plugin = {}
    return gate.run(engine)
end

local function run_combined_only()
    -- shards = nil is the pre-fix code path: every value on the combined Set
    local saved = gate.shards
    gate.shards = nil
    kong.ctx.plugin = {}
    local m = gate.run(engine)
    gate.shards = saved
    return m
end

local function same(a, b)
    for k in pairs(a) do if not b[k] then return false end end
    for k in pairs(b) do if not a[k] then return false end end
    return true
end

local function count(t) local n = 0 for _ in pairs(t) do n = n + 1 end return n end

math.randomseed(20261102)
local PRINT = {}
for c = 33, 126 do
    local ch = string.char(c)
    if not ch:find('[<>"\\&%%]') then PRINT[#PRINT + 1] = ch end
end
local function rnd_printable(n)
    local t = {}
    for i = 1, n do t[i] = PRINT[math.random(#PRINT)] end
    return table.concat(t)
end
local function rnd_bytes(n)
    local t = {}
    for i = 1, n do t[i] = string.char(math.random(0, 255)) end
    return table.concat(t)
end

-- 1. equivalence -----------------------------------------------------------
print("equivalence (sharded vs combined Set):")
local long_attack = rnd_printable(4000) .. " 1' UNION SELECT password FROM users-- "
                    .. rnd_printable(4000)
local cases = {
    { "short benign",   { a = "hello world", b = "john.doe@example.com", c = "42" } },
    { "short attacks",  { a = "<script>alert(1)</script>", b = "1 or 1=1--", c = ";cat /etc/passwd", d = "../../etc/shadow" } },
    { "long attack",    { a = long_attack } },
    { "random 20 KB",   { a = rnd_bytes(20480) } },
    { "printable 20 KB", { a = rnd_printable(20480) } },
}
do
    local many = {}
    for i = 1, 120 do many["a" .. i] = rnd_printable(300) end
    many.x = "<img src=x onerror=alert(1)>"
    cases[#cases + 1] = { "120 x 300 B printable + xss", many }
end
for _, c in ipairs(cases) do
    set_request(c[2])
    local want = run_combined_only()
    set_request(c[2])
    local got = run_sharded()
    ok(same(want, got), string.format("%-28s %3d ids", c[1], count(got)))
end

-- 2. bounded time on high-entropy input ------------------------------------
-- The bound sits well above what the sharded scan takes and well below what
-- the combined Set alone took on the same input.
print("time on high-entropy input:")
local BOUND = 0.5
for _, c in ipairs({
    { "printable 100 KB", { a = rnd_printable(102400) } },
    { "random 100 KB",    { a = rnd_bytes(102400) } },
    { "250 x 400 B printable", (function()
        local t = {}
        for i = 1, 250 do t["a" .. i] = rnd_printable(400) end
        return t
    end)() },
}) do
    set_request(c[2])
    local t0 = os.clock()
    run_sharded()
    local dt = os.clock() - t0
    ok(dt < BOUND, string.format("%-24s %.3f s (bound %.1f s)", c[1], dt, BOUND))
end

-- 3. a shard that failed to build ------------------------------------------
print("missing shard:")
if gate.shards then
    local sh = gate.shards[1]
    local saved = sh.handle
    sh.handle = false
    set_request({ a = rnd_printable(2048) })  -- > LONG_VALUE: sharded path
    local m = run_sharded()
    sh.handle = saved
    ok(m[sh.id] == true, "pattern of an unbuilt shard is reported matched")
else
    ok(false, "pattern of an unbuilt shard is reported matched (no shards)")
end

print(string.format("\nre2_gate_entropy: %d passed, %d failed", pass, fail))
os.exit(fail == 0 and 0 or 1)
