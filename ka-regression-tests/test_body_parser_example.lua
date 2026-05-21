-- Simple example of using the test_helper to run tests with the body parser

--[[
    Get full path of this script and add it to package.path
]]--
local full_path_lua_script = debug.getinfo(1, "S").source:sub(2)
local script_path = full_path_lua_script:match("(.*/)") or "./"
package.path = script_path..'?.lua;'..script_path..'../kong/plugins/karna/modules/?.lua;'..script_path..'/?.lua;' ..package.path

-- First, load the test helper
local test_helper = require "test_helper"

-- Initialize the globals and load the module
test_helper.setup_environment()

-- Now we can safely require the module
local body_parser = require "ka_body_parser"

-- Set custom debug functions for testing
body_parser.debug = function(m) print("[DEBUG] " .. tostring(m)) end
body_parser.inspect = function(t) 
    print("[INSPECT]")
    for k, v in pairs(t) do
        print("  " .. tostring(k) .. ": " .. tostring(v))
    end
end

-- Simple test to verify it works
print("\nTest case: Basic URL-encoded parsing")

local result = body_parser:urlencoded("request.body", "param1=value1&param2=value2", false)

print("\nTest Results:")
for _, item in ipairs(result) do
    for k, v in pairs(item) do
        print(k .. " = " .. v)
    end
end

print("\nTest completed successfully")