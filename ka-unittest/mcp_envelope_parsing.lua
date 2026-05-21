-- ka-unittest/mcp_envelope_parsing.lua
--
-- Pure-helper tests for ka_mcp._validate_jsonrpc and _lookup_path.
-- Run from repo root:   luajit ka-unittest/mcp_envelope_parsing.lua
--
-- We bypass the Kong require chain: load only the helpers we test.
-- Anything that touches ngx / kong / cjson stays out of this file.

package.path = "./kong/plugins/karna/modules/?.lua;" .. package.path

-- Stub the modules ka_mcp.lua itself requires so we don't drag in OpenResty.
package.preload["cjson.safe"] = function()
    return { decode = function(s) return nil end, encode = function(t) return nil end }
end
package.preload["kong.plugins.karna.ka_mcp_sse"] = function()
    return { new = function() return {} end, feed = function() return {} end,
             parse_event = function() return {} end, serialize = function() return "" end }
end

local ok, ka_mcp = pcall(require, "ka_mcp")
if not ok then
    io.stderr:write("FAIL: cannot load ka_mcp.lua: " .. tostring(ka_mcp) .. "\n")
    os.exit(1)
end

local failures = 0
local function check(label, cond, hint)
    if cond then
        print("  PASS  " .. label)
    else
        print("  FAIL  " .. label .. (hint and ("  (" .. hint .. ")") or ""))
        failures = failures + 1
    end
end

print("== _validate_jsonrpc ==")

-- Valid request
local ok1, kind1 = ka_mcp._validate_jsonrpc({ jsonrpc = "2.0", method = "tools/call", id = 1, params = {} })
check("valid request shape",                 ok1 and kind1 == "request")

-- Valid notification (no id)
local ok2, kind2 = ka_mcp._validate_jsonrpc({ jsonrpc = "2.0", method = "notifications/initialized" })
check("valid notification (no id)",          ok2 and kind2 == "notification")

-- Valid response with result
local ok3, kind3 = ka_mcp._validate_jsonrpc({ jsonrpc = "2.0", id = 7, result = { tools = {} } })
check("valid response with result",          ok3 and kind3 == "response")

-- Valid error response
local ok4, kind4 = ka_mcp._validate_jsonrpc({ jsonrpc = "2.0", id = 7, error = { code = -32601, message = "" } })
check("valid error response",                ok4 and kind4 == "error")

-- Invalid: missing jsonrpc
local ok5 = ka_mcp._validate_jsonrpc({ method = "tools/call", id = 1 })
check("invalid: missing jsonrpc field",      not ok5)

-- Invalid: wrong jsonrpc version
local ok6 = ka_mcp._validate_jsonrpc({ jsonrpc = "1.0", method = "tools/call", id = 1 })
check("invalid: jsonrpc != 2.0",             not ok6)

-- Invalid: method+result both present
local ok7 = ka_mcp._validate_jsonrpc({ jsonrpc = "2.0", method = "x", id = 1, result = {} })
check("invalid: method and result together", not ok7)

-- Invalid: not a table
local ok8 = ka_mcp._validate_jsonrpc("garbage")
check("invalid: scalar passed in",           not ok8)

print("== _lookup_path ==")

local sample = {
    tool = {
        name = "filesystem_write",
        arguments = { path = "/etc/passwd", mode = 0644 },
    },
    list = { "alpha", "beta", "gamma" },
}

check("simple key",                          ka_mcp._lookup_path(sample, "tool.name") == "filesystem_write")
check("nested key",                          ka_mcp._lookup_path(sample, "tool.arguments.path") == "/etc/passwd")
check("array by 1-based index",              ka_mcp._lookup_path(sample, "list.1") == "alpha")
check("missing path returns nil",            ka_mcp._lookup_path(sample, "tool.bogus.path") == nil)
check("non-table input returns nil",         ka_mcp._lookup_path("string", "anything") == nil)
check("nil input returns nil",               ka_mcp._lookup_path(nil, "x") == nil)

if failures > 0 then
    io.stderr:write(("\n%d failure(s)\n"):format(failures))
    os.exit(1)
end
print("\nall green")
