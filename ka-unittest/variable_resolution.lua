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

-- Two distinct client IPs: the transport peer (a load balancer, say) and the
-- forwarded client Kong derives from X-Forwarded-For + trusted_ips. They must
-- not collapse into each other — an IP allow-list behind a CDN needs the second.
local PEER_IP      = "10.0.0.7"
local FORWARDED_IP = "203.0.113.9"

_G.ngx = {
    get_phase = function() return PHASE end,
    var = { remote_addr = PEER_IP },
}
_G.kong = {
    log = { err = function() end, warn = function() end, debug = function() end },
    request = {
        get_path            = function() return REQUEST.path end,
        get_raw_path        = function() return REQUEST.raw_path end,
        get_path_with_query = function() return REQUEST.path_with_query end,
        get_method          = function() return "GET" end,
    },
    client = {
        get_forwarded_ip = function() return FORWARDED_IP end,
    },
}

local ka_compile = dofile("./kong/plugins/karna/modules/ka_compile.lua")

-- Minimal engine stand-in: the resolvers for raw_path/basename/the client-IP
-- family delegate to engine helpers, so provide just those. These mirror the
-- real getters in ka_engine.lua — if one is renamed there, the resolver calls a
-- name this table does not have and the test errors out rather than passing on a
-- stale stub.
local engine = {
    __get_values_request_raw_path = function()
        return { ["request.raw_path"] = REQUEST.raw_path }, nil
    end,
    __get_values_remote_addr = function()
        return { ["request.remote_addr"] = ngx.var.remote_addr }, nil
    end,
    __get_values_forwarded_addr = function()
        return { ["request.forwarded_addr"] = kong.client.get_forwarded_ip() }, nil
    end,
    -- Flattened ARGS as the body parser emits them: source-prefixed keys, one
    -- per field. The names deliberately carry Lua pattern metacharacters, each
    -- paired with a decoy whose name is what the unescaped pattern would match.
    __get_values_request_args = function()
        return {
            ["request.query.value:wc-ajax"]                    = "checkout",
            ["request.query.value:wcajax"]                     = "decoy-hyphen",
            ["request.body.urlencode.value:data[wp_autosave]"] = "blob",
            ["request.body.urlencode.value:dataXwp_autosaveY"] = "decoy-bracket",
            ["request.body.json.value:payer.name.surname"]     = "Rossi",
            ["request.body.json.value:payerXnameXsurname"]     = "decoy-dot",
        }, nil
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
print("client IP variable resolvers:")
-- ---------------------------------------------------------------------------

-- SecLang maps REMOTE_ADDR to request.remote_addr, and that mapping existed for
-- a long time with NO resolver behind it: every rule targeting the client IP
-- (CRS 905100/905110, any IP allow/deny list) silently never matched. Exactly
-- the failure mode this file exists to catch.
values, why = resolve("request.remote_addr")
check("request.remote_addr has a resolver", values ~= nil, tostring(why))
check("request.remote_addr resolves the transport peer",
      values and values["request.remote_addr"] == PEER_IP,
      values and tostring(values["request.remote_addr"]))

values, why = resolve("request.forwarded_addr")
check("request.forwarded_addr has a resolver", values ~= nil, tostring(why))
check("request.forwarded_addr resolves Kong's forwarded client",
      values and values["request.forwarded_addr"] == FORWARDED_IP,
      values and tostring(values["request.forwarded_addr"]))

-- The whole point of shipping both: behind a proxy they differ, and a rule
-- author picking one must not silently get the other.
check("remote_addr and forwarded_addr stay distinct",
      resolve("request.remote_addr")["request.remote_addr"]
        ~= resolve("request.forwarded_addr")["request.forwarded_addr"])

-- ---------------------------------------------------------------------------
print("")
print("argument selector, names with Lua pattern metacharacters:")
-- ---------------------------------------------------------------------------

-- The selector name is spliced into a suffix pattern, so it has to be escaped
-- first. Unescaped, `wc-ajax` reads as "w, zero or more c, ajax": the selector
-- missed the argument it named AND resolved one it did not
-- (`?wcajax=` matched `request.arg.value:wc-ajax`). Same class of bug on the
-- removal side, where a `ctl:...;ARGS:g-recaptcha-response` exclusion removed
-- nothing. Application parameter names are not ours to choose — wc-ajax,
-- g-recaptcha-response and data[wp_autosave] are all real — so escaping is the
-- only fix.
local function keys_of(t)
    local out = {}
    for k in pairs(t or {}) do out[#out + 1] = k end
    table.sort(out)
    return table.concat(out, ",")
end

values = resolve("request.arg.value:wc-ajax")
check("hyphenated name resolves the argument it names",
      keys_of(values) == "request.query.value:wc-ajax", keys_of(values))

values = resolve("request.arg.value:wcajax")
check("...and does not steal the hyphen-free sibling",
      keys_of(values) == "request.query.value:wcajax", keys_of(values))

values = resolve("request.arg.value:data[wp_autosave]")
check("bracketed name matches literally, not as a character class",
      keys_of(values) == "request.body.urlencode.value:data[wp_autosave]", keys_of(values))

values = resolve("request.arg.value:payer.name.surname")
check("dotted name matches a literal dot, not any character",
      keys_of(values) == "request.body.json.value:payer.name.surname", keys_of(values))

values = resolve("request.arg.value:nosuchargument")
check("a name that matches nothing resolves to nothing", keys_of(values) == "", keys_of(values))

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
