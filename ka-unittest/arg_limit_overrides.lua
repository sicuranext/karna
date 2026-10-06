-- ka-unittest/arg_limit_overrides.lua
--
-- `limit_arg_num_overrides`: a per-path replacement for the always-on
-- `limit_arg_num` gate. The first entry whose path_rx matches the normalized
-- request path (and whose methods, when given, include the request method)
-- sets the limit for that request; no match = the service limit.
--
-- Pinned here:
--   1. ka_arg_limits.compile / resolve: order, methods (case-insensitive,
--      absent = any), invalid entries dropped with an error, the 32-entry cap.
--   2. ka_arg_limits.validate_path_rx (the schema custom_validator): a pattern
--      the regex engine rejects returns a clear error.
--   3. the gate end to end, through handler.lua's resolver and the real
--      engine: under / over the override, over the service limit on another
--      path, a method outside the override, no overrides configured, the
--      block message, and the early stop (query over the limit = body never
--      parsed).
--
-- The real regex engines (RE2 / PCRE) are not available under plain Lua, so
-- ngx.re.find is stood in by Lua patterns here; the patterns used below mean
-- the same thing in both syntaxes. The RE2 rejection path is covered live
-- against the Admin API (see the PR).
--
-- Run from repo root:
--   lua    ka-unittest/arg_limit_overrides.lua
--   luajit ka-unittest/arg_limit_overrides.lua

local H = dofile("./ka-unittest/_engine_harness.lua")
local engine = H.engine

-- Lua-pattern stand-in for ngx.re.find: a malformed pattern returns the
-- (nil, nil, err) triple ngx.re.find gives on a compile error.
ngx.re.find = function(s, p)
    local ok, from, to = pcall(string.find, s, p)
    if not ok then return nil, nil, from end
    return from, to
end

local fails = 0
local function ok(cond, name, detail)
    if cond then print("  ok  - " .. name)
    else print("  FAIL- " .. name .. (detail and ("  (" .. tostring(detail) .. ")") or "")); fails = fails + 1 end
end

local ka_arg_limits = dofile("./kong/plugins/karna/modules/ka_arg_limits.lua")
package.preload["kong.plugins.karna.ka_arg_limits"] = function() return ka_arg_limits end

-- ============================================================
print("1. ka_arg_limits.compile / resolve")
-- ============================================================
local compiled, errs = ka_arg_limits.compile({
    { path_rx = "^/a$", methods = { "post" }, limit = 10 },
    { path_rx = "^/a$", limit = 20 },
    { path_rx = "([a-", limit = 30 },
    { path_rx = "^/b$", limit = 0 },
    { path_rx = "^/c", limit = 40 },
})
ok(#compiled == 3, "three valid entries compiled", #compiled)
ok(#errs == 2, "two entries dropped with an error", #errs)
ok(errs[1] and errs[1]:find("entry #3", 1, true) and errs[1]:find("invalid path_rx", 1, true),
   "bad regex named in the error", errs[1])
ok(errs[2] and errs[2]:find("entry #4", 1, true), "limit 0 rejected", errs[2])

local e = ka_arg_limits.resolve(compiled, "POST", "/a")
ok(e and e.limit == 10, "first match wins (POST /a → 10)", e and e.limit)
e = ka_arg_limits.resolve(compiled, "get", "/a")
ok(e and e.limit == 20, "method outside the first entry falls to the next (GET /a → 20)", e and e.limit)
e = ka_arg_limits.resolve(compiled, "PUT", "/c/deeper")
ok(e and e.limit == 40, "entry without methods matches any method", e and e.limit)
ok(ka_arg_limits.resolve(compiled, "POST", "/zzz") == nil, "no match → nil")
ok(ka_arg_limits.resolve({}, "POST", "/a") == nil, "empty list → nil")
ok(ka_arg_limits.resolve(nil, "POST", "/a") == nil, "nil list → nil")

local many = {}
for i = 1, 40 do many[i] = { path_rx = "^/p" .. i .. "$", limit = i } end
local capped, cap_errs = ka_arg_limits.compile(many)
ok(#capped == ka_arg_limits.MAX_OVERRIDES and #cap_errs == 1, "more than 32 entries: the rest ignored",
   #capped .. "/" .. #cap_errs)

-- ============================================================
print("\n2. validate_path_rx (schema custom_validator)")
-- ============================================================
ok(ka_arg_limits.validate_path_rx("^/forms/big$") == true, "valid pattern accepted")
local v, verr = ka_arg_limits.validate_path_rx("([a-")
ok(v == nil and verr and verr:find("invalid path_rx '([a-'", 1, true), "invalid pattern rejected with a clear message", verr)
v, verr = ka_arg_limits.validate_path_rx("")
ok(v == nil and verr, "empty pattern rejected", verr)

-- ============================================================
print("\n3. the gate (handler resolver + real engine)")
-- ============================================================
for _, name in ipairs({ "ka_re2_gate", "ka_header_names", "ka_tls", "ka_global_rules", "ka_redact" }) do
    package.preload["kong.plugins.karna." .. name] = package.preload["kong.plugins.karna." .. name]
        or function() return {} end
end
package.preload["kong.plugins.karna.version"] = function()
    return { version = "0.0.0-test", commit = "deadbee", commit_short = "deadbee", built_at = "test" }
end
local exits = {}
kong.response.exit = function(status) exits[#exits + 1] = status end
kong.response.set_header = kong.response.set_header or function() end
kong.log.err = function() end

local handler = dofile("./kong/plugins/karna/handler.lua")
local resolve = handler._internals.resolve_arg_limit_override
ok(type(resolve) == "function", "handler._internals.resolve_arg_limit_override present")

local function args(n, prefix)
    local t = {}
    for i = 1, n do t[i] = (prefix or "a") .. i .. "=1" end
    return table.concat(t, "&")
end
local function request(method, path, body, query)
    H.request.method    = method
    H.request.path      = path
    H.request.raw_path  = path
    H.request.raw_query = query or ""
    H.request.headers   = body and { ["Content-Type"] = "application/x-www-form-urlencoded",
                                     ["Content-Length"] = tostring(#body) } or {}
    H.request.body      = body
    H.reset()
    kong.ctx.plugin.ka_matched_rules = {}
    exits = {}
end
local function last_message()
    local m = kong.ctx.plugin.ka_matched_rules
    return m[#m] and m[#m].rule.message
end
local function gate(conf)
    return engine:check_request_arg_count(conf, resolve(conf))
end

local CONF = {
    __plugin_id = "p1", __seq__ = 1,
    engine_blocking_mode = true,
    limit_arg_num = 3,
    try_bas64decode_if_possible = false,
    limit_arg_num_overrides = {
        { path_rx = "^/forms/big$", methods = { "POST" }, limit = 10 },
    },
}

request("POST", "/forms/big", args(8))
gate(CONF)
ok(#exits == 0 and #kong.ctx.plugin.ka_matched_rules == 0, "path matches, under the override (8 <= 10): passes")

request("POST", "/forms/big", args(12))
gate(CONF)
ok(exits[1] == 403, "path matches, over the override: 403", exits[1])
ok(last_message() == "Request argument count limit reached (11 > 10, override ^/forms/big$)",
   "block message names the limit and the override", last_message())

request("POST", "/other", args(5))
gate(CONF)
ok(exits[1] == 403, "path does not match, over the service limit: 403", exits[1])
ok(last_message() == "Request argument count limit reached (4 > 3)",
   "service-limit message unchanged in shape", last_message())

request("PUT", "/forms/big", args(5))
gate(CONF)
ok(exits[1] == 403, "method outside the override: service limit applies (403)", exits[1])

local NO_OVERRIDES = { __plugin_id = "p2", __seq__ = 1, engine_blocking_mode = true,
                       limit_arg_num = 3, try_bas64decode_if_possible = false,
                       limit_arg_num_overrides = {} }
request("POST", "/forms/big", args(3))
gate(NO_OVERRIDES)
ok(#exits == 0, "no overrides: at the service limit passes")
request("POST", "/forms/big", args(4))
gate(NO_OVERRIDES)
ok(exits[1] == 403 and last_message() == "Request argument count limit reached (4 > 3)",
   "no overrides: over the service limit blocks as before", last_message())
ok(resolve(NO_OVERRIDES) == nil and resolve({ limit_arg_num = 3 }) == nil,
   "no overrides (empty or absent): nothing resolved")

-- detection mode: the gate still reports "over" so the handler skips the scan
local DETECT = { __plugin_id = "p3", __seq__ = 1, engine_blocking_mode = false,
                 limit_arg_num = 3, try_bas64decode_if_possible = false,
                 limit_arg_num_overrides = CONF.limit_arg_num_overrides }
request("POST", "/forms/big", args(12))
ok(gate(DETECT) == true and #exits == 0, "detection mode: over the override returns true, no exit")

-- early stop: a query already over the limit never gets its body parsed
request("POST", "/other", args(50, "b"), args(4, "q"))
gate(CONF)
ok(exits[1] == 403, "query over the service limit: 403", exits[1])
ok(kong.ctx.plugin.ka_raw_body == nil, "body never read once the query passed the limit")

-- ============================================================
print("")
if fails == 0 then print("ALL PASS") else print(fails .. " test(s) failed"); os.exit(1) end
