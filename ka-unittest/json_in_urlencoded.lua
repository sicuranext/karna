-- ka-unittest/json_in_urlencoded.lua
--
-- Guards the "JSON embedded in a urlencoded value" feature in
-- ka_body_parser:urlencoded. For a body like `a=b&c={"foo":"bar"}` the parser
-- must expose BOTH:
--   * the raw value as one string  (request.body.urlencode.value:c)
--   * the flattened nested fields  (request.body.urlencode.json:c.value:foo)
--
-- The flattening regressed silently: _M.json was refactored to return a flat
-- dict { [label] = value }, but the merge loop in _M.urlencoded still expected
-- the old array-of-single-key-tables shape (`if type(vv) == "table"`), so every
-- nested key was discarded. Only the raw string survived. This test fails on
-- that buggy shape and passes once the merge iterates the flat dict directly.
--
-- Run from repo root:
--   lua    ka-unittest/json_in_urlencoded.lua
--   luajit ka-unittest/json_in_urlencoded.lua

package.path = "./kong/plugins/karna/modules/?.lua;" .. package.path

local function map_kpk(short, long)
    package.preload[long] = function()
        return dofile("./kong/plugins/karna/modules/" .. short .. ".lua")
    end
end

-- ---------------------------------------------------------------------------
-- minimal but correct JSON decoder (lua5.4 has no cjson; we need REAL decoding
-- so the parser's flatten actually runs on the test payloads)
-- ---------------------------------------------------------------------------
local function json_decode(s)
    local i = 1
    local parse_value
    local function skip_ws() while i <= #s and s:sub(i, i):match("%s") do i = i + 1 end end
    local function parse_string()
        i = i + 1 -- opening quote
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
            skip_ws(); local k = parse_string(); skip_ws()
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
        elseif c == 't' then i = i + 4; return true
        elseif c == 'f' then i = i + 5; return false
        elseif c == 'n' then i = i + 4; return nil
        else
            local num = s:match("^%-?%d+%.?%d*[eE]?[%+%-]?%d*", i)
            if not num or num == "" then error("bad token") end
            i = i + #num; return tonumber(num)
        end
    end
    return parse_value()
end

-- ---------------------------------------------------------------------------
-- mocks (mirrors ka-unittest/transformations.lua, minus what we don't touch)
-- ---------------------------------------------------------------------------
_G.ngx = {
    re = { match = function() return nil end, gmatch = function() return function() return nil end end },
    unescape_uri = function(s)
        s = s:gsub("+", " "):gsub("%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end)
        return s
    end,
    log = function() end,
}
_G.kong = {
    mocked = false,
    log = { debug = function() end, warn = function() end, err = function() end },
    request  = { get_header = function() return nil end, get_raw_body = function() return nil end },
    response = { get_header = function() return nil end },
    ctx = { plugin = {} },
}

package.preload["cjson"] = function()
    return { decode = json_decode, encode = function() return "" end,
             encode_empty_table_as_object = function() end }
end
package.preload["ngx.base64"] = function()
    return { encode_base64url = function(s) return s end, decode_base64url = function(s) return s end }
end
package.preload["kong.plugins.karna.ka_utils"] = function()
    return { urldecode = function(_, s) return s end,
             base64_decode = function() return nil, false end }
end
package.preload["kong.plugins.karna.ka_multipart"] = function()
    return { parse = function() return nil, "stub" end }
end
map_kpk("ka_body_parser", "kong.plugins.karna.ka_body_parser")

local bp = require "kong.plugins.karna.ka_body_parser"

-- ---------------------------------------------------------------------------
-- assertions
-- ---------------------------------------------------------------------------
local failures = 0
local function check(name, cond, detail)
    if cond then
        print("  ok   - " .. name)
    else
        failures = failures + 1
        print("  FAIL - " .. name .. (detail and ("  (" .. detail .. ")") or ""))
    end
end
-- find a values entry whose key contains `.json:` and whose value == want
local function flattened_value_exists(values, want)
    for k, v in pairs(values) do
        if k:find(".json:", 1, true) and v == want then return k end
    end
    return nil
end

print("JSON-in-urlencoded flattening:")

-- 1. marker is the value of a nested JSON key
local v1 = bp:urlencoded("request.body.urlencode", 'a=b&c={"foo":"KARNA_PWNED"}', false)
check("raw JSON value is exposed as the arg (ModSec-compat)",
      v1["request.body.urlencode.value:c"] == '{"foo":"KARNA_PWNED"}',
      tostring(v1["request.body.urlencode.value:c"]))
local k1 = flattened_value_exists(v1, "KARNA_PWNED")
check("nested JSON value is flattened into a queryable key", k1 ~= nil,
      "no .json: key holds the nested value")
check("flattened key is the expected namespace",
      v1["request.body.urlencode.json:c.value:foo"] == "KARNA_PWNED",
      "found key = " .. tostring(k1))

-- 2. deeper nesting
local v2 = bp:urlencoded("request.body.urlencode", 'a=b&c={"x":{"y":"DEEP_MARK"}}', false)
check("deeply nested JSON value is flattened",
      flattened_value_exists(v2, "DEEP_MARK") ~= nil)

-- 3. a plain (non-JSON) value must NOT create a json: namespace
local v3 = bp:urlencoded("request.body.urlencode", 'a=b&c=plain_value', false)
check("plain value is exposed raw", v3["request.body.urlencode.value:c"] == "plain_value")
local any_json = false
for k in pairs(v3) do if k:find(".json:", 1, true) then any_json = true end end
check("plain value does not produce a json: namespace", not any_json)

-- 4. a value that starts like JSON but is invalid must not crash / not flatten
local ok4, v4 = pcall(function()
    return bp:urlencoded("request.body.urlencode", 'a=b&c={not valid json', false)
end)
check("invalid JSON value is tolerated (no crash)", ok4)
if ok4 then
    check("invalid JSON still exposes the raw value",
          v4["request.body.urlencode.value:c"] == "{not valid json")
end

print("")
if failures == 0 then
    print("ALL PASS")
    os.exit(0)
else
    print(failures .. " FAILURE(S)")
    os.exit(1)
end
