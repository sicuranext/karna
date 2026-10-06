-- ka_arg_limits — per-path overrides for the `limit_arg_num` gate.
--
-- `limit_arg_num` is an always-on gate that runs before the rule loop, so no
-- rule control can raise it for one endpoint. When a single endpoint
-- legitimately sends far more arguments than the rest of the service, raising
-- the service-wide limit exposes every other endpoint to the parse + scan cost
-- of a huge request. `limit_arg_num_overrides` scopes the higher limit to the
-- requests that need it:
--
--   limit_arg_num_overrides = {
--     { path_rx = "^/[a-z]{2}/forms/submit$", methods = { "POST" }, limit = 8192 },
--   }
--
-- The first entry whose `path_rx` matches the normalized request path (and
-- whose `methods`, when given, contain the request method) replaces
-- `limit_arg_num` for that request. No match = the service limit.
--
-- Regex engine: RE2 when libka_re2.so is loadable (linear time, the same
-- engine as the @rx operator), else ngx.re (PCRE). The search is unanchored,
-- so an override meant for one path must carry `^` and `$`. `.` does not
-- match a newline and `$` matches only at the very end of the path (PCRE runs
-- with the D flag), so a path with a trailing encoded newline does not pick
-- up an override written for the clean path.
--
-- Pure Lua: no kong globals, ngx only behind a guard, ka_re2 required lazily
-- (it needs the LuaJIT FFI). `compile` takes an optional compiler so the unit
-- test (ka-unittest/arg_limit_overrides.lua) runs under plain Lua.

local type         = type
local ipairs       = ipairs
local pcall        = pcall
local tostring     = tostring
local string_upper = string.upper

local _M = {}

-- Upper bound on the number of entries, enforced by the schema (`len_max`).
_M.MAX_OVERRIDES = 32

local re2_mod
local re2_checked = false

local function re2()
    if not re2_checked then
        re2_checked = true
        local ok, mod = pcall(require, "kong.plugins.karna.ka_re2")
        if ok and mod and mod.available() then
            re2_mod = mod
        end
    end
    return re2_mod
end

-- Default compiler: pattern -> matcher(path) -> bool, or nil + error.
local function default_compiler(pattern)
    local r = re2()
    if r then
        local h = r.re_compile(pattern, false)
        if not h then
            return nil, "not a valid RE2 regular expression"
        end
        return function(s) return r.re_match(h, s) ~= nil end
    end

    local re = ngx and ngx.re
    if not (re and re.find) then
        return nil, "no regex engine available"
    end
    local _, _, err = re.find("", pattern, "joD")
    if err then
        return nil, "not a valid regular expression: " .. tostring(err)
    end
    local find = re.find
    return function(s) return find(s, pattern, "joD") ~= nil end
end

-- Schema custom_validator for `path_rx`: true, or nil + a message the Admin
-- API returns as the field error.
_M.validate_path_rx = function(pattern)
    if type(pattern) ~= "string" or pattern == "" then
        return nil, "path_rx must be a non-empty string"
    end
    local m, err = default_compiler(pattern)
    if not m then
        return nil, "invalid path_rx '" .. pattern .. "': " .. tostring(err)
    end
    return true
end

-- Compile the configured entries into matchers, in order. Returns the
-- compiled list and an array of error strings for the entries that were
-- skipped (an entry the schema let through but this node cannot compile,
-- e.g. validated on a node without RE2). A skipped entry falls back to the
-- service limit for its path, never to "no limit".
_M.compile = function(entries, compiler)
    compiler = compiler or default_compiler
    local out, errs = {}, {}
    if type(entries) ~= "table" then
        return out, errs
    end
    for i, e in ipairs(entries) do
        if #out >= _M.MAX_OVERRIDES then
            errs[#errs + 1] = "entry #" .. i .. " ignored: more than "
                .. _M.MAX_OVERRIDES .. " overrides"
            break
        end
        local limit = type(e) == "table" and e.limit
        local path_rx = type(e) == "table" and e.path_rx
        if type(path_rx) ~= "string" or path_rx == ""
           or type(limit) ~= "number" or limit <= 0 then
            errs[#errs + 1] = "entry #" .. i .. " ignored: needs path_rx and limit > 0"
        else
            local match, err = compiler(path_rx)
            if not match then
                errs[#errs + 1] = "entry #" .. i .. " ignored: invalid path_rx '"
                    .. path_rx .. "': " .. tostring(err)
            else
                local methods
                if type(e.methods) == "table" and #e.methods > 0 then
                    methods = {}
                    for _, m in ipairs(e.methods) do
                        if type(m) == "string" then
                            methods[string_upper(m)] = true
                        end
                    end
                end
                out[#out + 1] = {
                    path_rx = path_rx,
                    limit   = limit,
                    methods = methods,
                    match   = match,
                }
            end
        end
    end
    return out, errs
end

-- First compiled entry matching (method, path), or nil.
_M.resolve = function(compiled, method, path)
    if type(compiled) ~= "table" or compiled[1] == nil then
        return nil
    end
    path = path or ""
    method = method and string_upper(method) or ""
    for i = 1, #compiled do
        local e = compiled[i]
        if (e.methods == nil or e.methods[method]) and e.match(path) then
            return e
        end
    end
    return nil
end

return _M
