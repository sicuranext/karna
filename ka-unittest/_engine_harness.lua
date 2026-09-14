-- ka-unittest/_engine_harness.lua
--
-- Loads the REAL engine — ka_engine.lua, ka_compile.lua, ka_body_parser.lua,
-- ka_utils.lua — under plain Lua (5.4 in CI, LuaJIT in the Kong image) behind
-- the same kong / ngx stubs transformations.lua uses, plus a request the test
-- can shape. Tests that need the real variable resolvers, the real
-- rule-control removal or a full `__match_rule_conditions` round trip load
-- it with `dofile("./ka-unittest/_engine_harness.lua")`; it is not a test
-- itself and CI does not run it directly.
--
-- Returned table:
--   H.engine        the ka_engine module
--   H.ka_compile    the ka_compile module (compile_variable_resolver, …)
--   H.body_parser   the ka_body_parser module
--   H.request       mutable request: method, path, raw_path, raw_query,
--                   headers (name → value, any case), body
--   H.reset()       fresh kong.ctx.plugin (caches + rule_controls store) and
--                   kong.ctx.shared; returns the rule_controls store
--   H.plugin_conf   default plugin_conf for H.match (fast path ON)
--   H.match(rule, plugin_conf)
--                   engine:__match_rule_conditions(rule, plugin_conf or H.plugin_conf)
--   H.attach_resolvers(rule)
--                   attach the stage-3 compiled resolvers to every condition
--                   (what compile_rules does at init_worker), so a test can
--                   drive the compiled path instead of the dispatcher
--
-- Everything the engine captures at load time (kong.request.get_header and
-- friends) is a closure over H.request, so a test may change the request
-- between cases without reloading anything.

package.path = "./kong/plugins/karna/modules/?.lua;" .. package.path

local H = {}

-- ---------------------------------------------------------------------------
-- the request under test
-- ---------------------------------------------------------------------------
H.request = {
    method    = "GET",
    path      = "/",
    raw_path  = "/",
    raw_query = "",
    headers   = {},
    body      = nil,
}

local function header(name)
    if type(name) ~= "string" then return nil end
    local want = name:lower()
    for k, v in pairs(H.request.headers) do
        if k:lower() == want then return v end
    end
    return nil
end

local function headers_lower()
    local out = {}
    for k, v in pairs(H.request.headers) do out[k:lower()] = v end
    return out
end

-- ---------------------------------------------------------------------------
-- pure-Lua stand-ins for the OpenResty primitives the resolvers touch
-- ---------------------------------------------------------------------------
local function lua_unescape_uri(s)
    s = tostring(s):gsub("+", " ")
    s = s:gsub("%%(%x%x)", function(hex) return string.char(tonumber(hex, 16)) end)
    return s
end

-- Strict base64 / base64url decoder. Returns nil on an alphabet violation or an
-- impossible length, like ngx.base64.decode_base64url; otherwise decodes, so a
-- short opaque token made of base64 characters ("YWJj") DOES decode — that is
-- exactly the production false-positive shape the cookie test relies on.
local B64 = {}
do
    local chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    for i = 1, #chars do B64[chars:sub(i, i)] = i - 1 end
    B64["+"] = 62; B64["-"] = 62
    B64["/"] = 63; B64["_"] = 63
end
local function lua_decode_base64(s)
    if type(s) ~= "string" then return nil end
    s = s:gsub("=+$", "")
    if s == "" then return "" end
    if #s % 4 == 1 then return nil end
    local out = {}
    local bits, nbits = 0, 0
    for i = 1, #s do
        local v = B64[s:sub(i, i)]
        if v == nil then return nil end
        bits = bits * 64 + v
        nbits = nbits + 6
        if nbits >= 8 then
            nbits = nbits - 8
            local byte = math.floor(bits / (2 ^ nbits))
            out[#out + 1] = string.char(byte % 256)
            bits = bits % (2 ^ nbits)
        end
    end
    return table.concat(out)
end

-- Minimal, correct JSON decoder (Lua 5.4 has no cjson; the body parser needs
-- REAL decoding so its flattener runs on the fixtures). Mirrors the one in
-- json_in_urlencoded.lua.
local function json_decode(s)
    if type(s) ~= "string" then error("not a string") end
    local i = 1
    local parse_value
    local function skip_ws() while i <= #s and s:sub(i, i):match("%s") do i = i + 1 end end
    local function parse_string()
        i = i + 1
        local buf = {}
        while i <= #s do
            local c = s:sub(i, i)
            if c == '"' then i = i + 1; return table.concat(buf) end
            if c == '\\' then
                local n = s:sub(i + 1, i + 1)
                if n == 'u' then
                    buf[#buf + 1] = string.char(tonumber(s:sub(i + 2, i + 5), 16) % 256); i = i + 6
                else
                    local map = { ['"'] = '"', ['\\'] = '\\', ['/'] = '/',
                                  n = '\n', t = '\t', r = '\r', b = '\b', f = '\f' }
                    buf[#buf + 1] = map[n] or n; i = i + 2
                end
            else
                buf[#buf + 1] = c; i = i + 1
            end
        end
        error("unterminated string")
    end
    local function parse_object()
        i = i + 1; local obj = {}; skip_ws()
        if s:sub(i, i) == '}' then i = i + 1; return obj end
        while true do
            skip_ws()
            if s:sub(i, i) ~= '"' then error("expected key") end
            local k = parse_string(); skip_ws()
            if s:sub(i, i) ~= ':' then error("expected :") end
            i = i + 1; obj[k] = parse_value(); skip_ws()
            local c = s:sub(i, i)
            if c == ',' then i = i + 1
            elseif c == '}' then i = i + 1; return obj
            else error("expected , or }") end
        end
    end
    local function parse_array()
        i = i + 1; local arr = {}; skip_ws()
        if s:sub(i, i) == ']' then i = i + 1; return arr end
        while true do
            arr[#arr + 1] = parse_value(); skip_ws()
            local c = s:sub(i, i)
            if c == ',' then i = i + 1
            elseif c == ']' then i = i + 1; return arr
            else error("expected , or ]") end
        end
    end
    parse_value = function()
        skip_ws(); local c = s:sub(i, i)
        if c == '{' then return parse_object()
        elseif c == '[' then return parse_array()
        elseif c == '"' then return parse_string()
        elseif s:sub(i, i + 3) == 'true' then i = i + 4; return true
        elseif s:sub(i, i + 4) == 'false' then i = i + 5; return false
        elseif s:sub(i, i + 3) == 'null' then i = i + 4; return nil
        else
            local num = s:match("^%-?%d+%.?%d*[eE]?[%+%-]?%d*", i)
            if not num or num == "" then error("bad token at " .. i) end
            i = i + #num; return tonumber(num)
        end
    end
    local v = parse_value()
    skip_ws()
    if i <= #s then error("trailing garbage") end
    return v
end

-- ---------------------------------------------------------------------------
-- ngx / kong stubs
-- ---------------------------------------------------------------------------
_G.ngx = {
    re = {
        match  = function() return nil end,
        gmatch = function() return function() return nil end end,
        gsub   = function(s) return s, 0, nil end,
    },
    unescape_uri  = lua_unescape_uri,
    escape_uri    = function(s) return s end,
    decode_base64 = lua_decode_base64,
    encode_base64 = function(s) return s end,
    sha1_bin      = function(s) return s end,
    md5           = function(s) return s end,
    var           = setmetatable({}, { __index = function(_, k)
                        if k == "remote_addr" then return "192.0.2.10" end
                        if k == "request_uri" then return H.request.raw_path end
                        return nil
                    end }),
    null          = nil,
    log           = function() end,
    NOTICE = 1, WARN = 2, ERR = 3, DEBUG = 4, INFO = 5,
    worker = { id = function() return 0 end },
    req    = {
        get_body_file = function() return nil end,
        get_post_args = function() return {} end,
        read_body     = function() end,
    },
    now    = function() return 0 end,
    time   = function() return 0 end,
    timer  = { at = function() return nil, "stub" end,
               every = function() return nil, "stub" end },
    config = { subsystem = "http" },
    get_phase = function() return "access" end,
}

_G.kong = {
    ctx = { plugin = {}, shared = {} },
    log = {
        debug   = function() end,
        warn    = function() end,
        err     = function() end,
        notice  = function() end,
        info    = function() end,
        inspect = function() end,
    },
    request = {
        get_header           = header,
        get_headers          = headers_lower,
        get_raw_body         = function() return H.request.body end,
        get_raw_query        = function() return H.request.raw_query end,
        get_path             = function() return H.request.path end,
        get_raw_path         = function() return H.request.raw_path end,
        get_path_with_query  = function()
            local q = H.request.raw_query
            return H.request.raw_path .. ((q and q ~= "") and ("?" .. q) or "")
        end,
        get_method           = function() return H.request.method end,
        get_http_version     = function() return 1.1 end,
        get_scheme           = function() return "http" end,
        get_host             = function() return "app.example" end,
        get_port             = function() return 80 end,
        get_forwarded_scheme = function() return "http" end,
        get_forwarded_host   = function() return "app.example" end,
        get_forwarded_port   = function() return 80 end,
        get_forwarded_path   = function() return H.request.path end,
        get_forwarded_prefix = function() return nil end,
    },
    client = {
        get_ip           = function() return "192.0.2.10" end,
        get_forwarded_ip = function() return "192.0.2.10" end,
    },
    service = {
        request  = {},
        response = {
            get_headers = function() return {} end,
            get_status  = function() return 200 end,
        },
    },
    response = {
        get_status = function() return 200 end,
        get_header = function() return nil end,
        get_source = function() return "service" end,
    },
    cache = { get = function() return nil end },
}

-- ---------------------------------------------------------------------------
-- module wiring: real modules where the tests need them, stubs elsewhere
-- ---------------------------------------------------------------------------
local function map_kpk(short, long)
    package.preload[long] = function()
        return dofile("./kong/plugins/karna/modules/" .. short .. ".lua")
    end
end
-- KARNA_UNIT_ENGINE=<path> loads that file as the engine instead of the working
-- tree's ka_engine.lua — for an A/B of a test against a previous engine (e.g.
-- `git show <rev>:kong/plugins/karna/modules/ka_engine.lua > /tmp/old.lua`).
local engine_override = os.getenv("KARNA_UNIT_ENGINE")

package.preload["cjson"] = function()
    return {
        decode = json_decode,
        encode = function() return "" end,
        encode_empty_table_as_object = function() end,
        empty_array = {},
    }
end
package.preload["cjson.safe"] = function()
    return {
        decode = function(s) local ok, v = pcall(json_decode, s); if ok then return v end return nil, v end,
        encode = function() return "" end,
    }
end
package.preload["ngx.base64"] = function()
    return {
        decode_base64url = function(s)
            local d = lua_decode_base64(s)
            if d == nil then return nil, "invalid" end
            return d
        end,
        encode_base64url = function(s) return s end,
    }
end
package.preload["inspect"]         = function() return function() return "" end end
package.preload["resty.ipmatcher"] = function() return { new = function() return { match = function() return false end } end } end
package.preload["resty.redis"]     = function() return { new = function() return {} end } end
package.preload["resty.http"]      = function() return { new = function() return {} end } end
package.preload["resty.lrucache"]  = function() return { new = function() return { get = function() return nil end, set = function() end, flush_all = function() end } end } end
package.preload["bit"]             = function() return { bor = function(a, b) return a + b end } end
package.preload["ffi"]             = function() return {
    new = function() return {} end, string = function() return "" end,
    typeof = function() return function() return {} end end, cdef = function() end,
    load = function() return {} end, metatype = function() end, gc = function(o) return o end,
} end

-- Every real module is mapped explicitly, the engine included: inside the Kong
-- image a bare `require "kong.plugins.karna.ka_engine"` would otherwise find
-- the luarocks-INSTALLED copy on package.path before the working tree, and the
-- test would silently run against yesterday's engine.
map_kpk("ka_utils",       "kong.plugins.karna.ka_utils")
map_kpk("ka_body_parser", "kong.plugins.karna.ka_body_parser")
map_kpk("ka_compile",     "kong.plugins.karna.ka_compile")
if engine_override and engine_override ~= "" then
    package.preload["kong.plugins.karna.ka_engine"] = function() return dofile(engine_override) end
else
    map_kpk("ka_engine",  "kong.plugins.karna.ka_engine")
end

package.preload["kong.plugins.karna.ka_multipart"]     = function() return { parse = function() return nil, "multipart not available in the unit harness" end } end
package.preload["kong.plugins.karna.ka_seclang"]       = function() return { parse = function() return {} end, collect_crs_conf_files = function() return {} end } end
package.preload["kong.plugins.karna.libinjection"]     = function() return { sqli_noquote = function() return false end, xss_data_state = function() return false end } end
package.preload["kong.plugins.karna.ka_rules_crs_fix"] = function() return { global_fps = {} } end
package.preload["kong.plugins.karna.ka_mcp"]           = function() return { _method_matches = function() return false end, _validate_jsonrpc = function() return true end } end
package.preload["kong.plugins.karna.ka_mcp_sse"]       = function() return {} end
package.preload["kong.plugins.karna.ka_re2"]           = function() return {
    available = function() return false end, re_match = function() return false end,
    build = function() return nil end, re_compile = function() return nil end,
} end
package.preload["kong.plugins.karna.ka_ac"]            = function() return {
    available = function() return false end, build = function() return nil end, match_any = function() return false end,
} end

-- ---------------------------------------------------------------------------
-- load
-- ---------------------------------------------------------------------------
local ok, engine = pcall(require, "kong.plugins.karna.ka_engine")
if not ok then
    io.stderr:write("FAIL: cannot load ka_engine.lua: " .. tostring(engine) .. "\n")
    os.exit(1)
end

H.engine      = engine
H.ka_compile  = require "kong.plugins.karna.ka_compile"
H.body_parser = require "kong.plugins.karna.ka_body_parser"

-- The per-request store, exactly as handler.lua:access initialises it.
local function new_store()
    return {
        ids = {},
        ids_targets = {},
        tags = {},
        removed_tags = {},
        remove_target_from_all_rules = {},
        engine_off = false,
        detection_only = false,
        engine_on = false,
        body_access_off = false,
        audit_request_body = false,
    }
end
H.new_store = new_store

function H.reset()
    _G.kong.ctx.plugin = {
        ka_value_cache    = {},
        ka_variable_cache = {},
        tx_variables      = {},
        rule_controls     = new_store(),
    }
    _G.kong.ctx.shared = {}
    return _G.kong.ctx.plugin.rule_controls
end

H.plugin_conf = { engine_fast_path = true, private_debug = false }

function H.match(rule, plugin_conf)
    return engine:__match_rule_conditions(rule, plugin_conf or H.plugin_conf)
end

function H.attach_resolvers(rule)
    for _, condition in ipairs(rule.conditions or {}) do
        local resolvers, any = {}, false
        for i, v in ipairs(condition.variables or {}) do
            local r = H.ka_compile.compile_variable_resolver(v)
            resolvers[i] = r
            if r then any = true end
        end
        condition._resolvers = any and resolvers or nil
    end
    return rule
end

H.reset()
return H
