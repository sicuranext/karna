-- ka-unittest/mcp_method_glob.lua
--
-- Pure-helper tests for ka_mcp._method_matches.
-- Run from repo root:   luajit ka-unittest/mcp_method_glob.lua

package.path = "./kong/plugins/karna/modules/?.lua;" .. package.path

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
local function check(label, cond)
    if cond then print("  PASS  " .. label) else print("  FAIL  " .. label); failures = failures + 1 end
end

print("== _method_matches ==")

-- Literals
check("literal exact match",            ka_mcp._method_matches("tools/call", { "tools/call" }))
check("literal mismatch",               not ka_mcp._method_matches("tools/list", { "tools/call" }))

-- Single-segment wildcard
check("tools/* matches tools/call",     ka_mcp._method_matches("tools/call", { "tools/*" }))
check("tools/* matches tools/list",     ka_mcp._method_matches("tools/list", { "tools/*" }))
check("tools/* does NOT match tools/sub/x",
                                        not ka_mcp._method_matches("tools/sub/x", { "tools/*" }))
check("tools/* does NOT match resources/list",
                                        not ka_mcp._method_matches("resources/list", { "tools/*" }))

-- Multi-segment wildcard
check("notifications/** matches notifications/initialized",
                                        ka_mcp._method_matches("notifications/initialized", { "notifications/**" }))
check("notifications/** matches notifications/resources/listChanged",
                                        ka_mcp._method_matches("notifications/resources/listChanged", { "notifications/**" }))
check("notifications/** does NOT match tools/call",
                                        not ka_mcp._method_matches("tools/call", { "notifications/**" }))

-- Multiple patterns (any-match)
check("any-of [tools/* notifications/**] matches notifications/x",
                                        ka_mcp._method_matches("notifications/x", { "tools/*", "notifications/**" }))
check("any-of [a b c] no match",
                                        not ka_mcp._method_matches("d/e", { "a/*", "b/*", "c/*" }))

-- Single pattern as string (not array)
check("single pattern as string",       ka_mcp._method_matches("tools/call", "tools/*"))

-- Edge cases
check("empty patterns list",            not ka_mcp._method_matches("tools/call", {}))
check("nil method input",               not ka_mcp._method_matches(nil, { "tools/*" }))
check("non-string method input",        not ka_mcp._method_matches(123, { "tools/*" }))
check("empty string pattern is ignored",not ka_mcp._method_matches("tools/call", { "" }))

-- Star at root catches everything
check("** catches anything",            ka_mcp._method_matches("a/b/c/d", { "**" }))

-- Patterns that contain pattern-special chars are escaped
check("dot in literal not treated as regex any",
                                        not ka_mcp._method_matches("toolsXcall", { "tools.call" }))
check("dot literal matches",            ka_mcp._method_matches("tools.call", { "tools.call" }))

if failures > 0 then
    io.stderr:write(("\n%d failure(s)\n"):format(failures))
    os.exit(1)
end
print("\nall green")
