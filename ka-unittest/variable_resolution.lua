-- ka-unittest/variable_resolution.lua
--
-- Guards the compiled variable resolvers in ka_compile for the URI family.
-- The trap being regression-tested: a variable that EXISTS in the access-phase
-- inspection_table but has no resolver silently resolves to nothing, so a rule
-- targeting it never matches and never errors — the worst failure mode for a
-- WAF rule. `request.path` was in exactly that state.
--
-- The three URI variables are deliberately distinct, so the test pins the
-- distinction rather than just "returns something":
--   request.path            nginx $uri     — dot segments resolved, percent
--                                            decoded (except %2F)
--   request.raw_path        verbatim       — as it came off the wire
--   request.path_with_query verbatim + querystring
--
-- Run from repo root:
--   lua    ka-unittest/variable_resolution.lua
--   luajit ka-unittest/variable_resolution.lua

package.path = "./kong/plugins/karna/modules/?.lua;" .. package.path

-- ka_compile requires its sibling modules through Kong's plugin require path,
-- which does not exist outside Kong; map the short names to the real files.
local function map_kpk(short, long)
    package.preload[long] = function()
        return dofile("./kong/plugins/karna/modules/" .. short .. ".lua")
    end
end
-- ka_re2 is FFI-only (LuaJIT); stub `ffi` so this test also runs under plain
-- Lua, which is what CI uses.
package.preload["ffi"] = function()
    return {
        cdef = function() end,
        load = function() return {} end,
        new = function() return {} end,
        string = function() return "" end,
        typeof = function() return function() return {} end end,
        metatype = function() end,
        gc = function(o) return o end,
    }
end
map_kpk("ka_re2", "kong.plugins.karna.ka_re2")

-- ---------------------------------------------------------------------------
-- ngx / kong stubs. The resolvers are phase-guarded, so the phase is part of
-- the contract under test.
-- ---------------------------------------------------------------------------
local PHASE = "access"

-- What the request looks like on the wire vs after nginx normalization. These
-- pairs are the values measured against a live Kong, not invented.
local REQUEST = {
    path            = "/y",            -- from /x/../y
    raw_path        = "/x/../y",
    path_with_query = "/x/../y?a=1",
}

_G.ngx = {
    get_phase = function() return PHASE end,
}
_G.kong = {
    log = { err = function() end, warn = function() end, debug = function() end },
    request = {
        get_path            = function() return REQUEST.path end,
        get_raw_path        = function() return REQUEST.raw_path end,
        get_path_with_query = function() return REQUEST.path_with_query end,
        get_method          = function() return "GET" end,
    },
}

local ka_compile = dofile("./kong/plugins/karna/modules/ka_compile.lua")

-- Minimal engine stand-in: the resolvers for raw_path/basename delegate to
-- engine helpers, so provide just those.
local engine = {
    __get_values_request_raw_path = function()
        return { ["request.raw_path"] = REQUEST.raw_path }, nil
    end,
}

local failures = 0
local function check(name, cond, detail)
    if cond then print("  ok   - " .. name)
    else failures = failures + 1; print("  FAIL - " .. name .. (detail and ("  (" .. detail .. ")") or "")) end
end

local function resolve(variable)
    local fn = ka_compile.compile_variable_resolver(variable)
    if not fn then return nil, "no resolver" end
    return fn(engine, {})
end

-- ---------------------------------------------------------------------------
print("URI variable resolvers:")
-- ---------------------------------------------------------------------------

local values, why = resolve("request.path")
check("request.path has a resolver", values ~= nil, tostring(why))
check("request.path resolves the normalized path",
      values and values["request.path"] == "/y",
      values and tostring(values["request.path"]))

values = resolve("request.raw_path")
check("request.raw_path resolves the verbatim path",
      values and values["request.raw_path"] == "/x/../y",
      values and tostring(values["request.raw_path"]))

values = resolve("request.path_with_query")
check("request.path_with_query keeps the querystring",
      values and values["request.path_with_query"] == "/x/../y?a=1",
      values and tostring(values["request.path_with_query"]))

-- The three must not collapse into each other: a rule author picking
-- request.raw_path to catch traversal must not silently get the normalized
-- value (and vice versa).
local p  = resolve("request.path")["request.path"]
local rp = resolve("request.raw_path")["request.raw_path"]
check("path and raw_path stay distinct", p ~= rp, tostring(p) .. " vs " .. tostring(rp))

-- ---------------------------------------------------------------------------
print("")
print("phase guard:")
-- ---------------------------------------------------------------------------

-- init_worker has no request; resolving there must yield nothing rather than
-- erroring inside kong.request.*.
PHASE = "init_worker"
check("request.path resolves to nothing in init_worker", resolve("request.path") == nil)
check("request.path_with_query resolves to nothing in init_worker",
      resolve("request.path_with_query") == nil)
PHASE = "access"

-- ---------------------------------------------------------------------------
print("")
print("unknown variables:")
-- ---------------------------------------------------------------------------

-- The compiler is allowed to refuse: an unknown variable returns nil and the
-- engine falls back to its own dispatcher. This is why a missing resolver is
-- silent, and why the checks above exist.
local fn = ka_compile.compile_variable_resolver("request.not_a_variable")
check("unknown variable has no compiled resolver (engine falls back)", fn == nil)

print("")
if failures == 0 then print("ALL PASS"); os.exit(0)
else print(tostring(failures) .. " FAILURE(S)"); os.exit(1) end
