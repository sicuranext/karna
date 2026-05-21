
--[[
    Get full path of this script and add it to package.path
]]--
local full_path_lua_script = debug.getinfo(1, "S").source:sub(2)
local script_path = full_path_lua_script:match("(.*/)") or "./"
package.path = script_path..'?.lua;'..script_path .. '../kong/plugins/karna/modules/?.lua;' .. package.path

-- First, load the test helper
local test_helper = require "test_helper"

-- Initialize the globals and load the module
test_helper.setup_environment()

-- include seclang module
local body      = require "ka_body_parser"
local inspect   = require "inspect"
local argparse  = require "argparse"

-- parse script arguments
local parser = argparse("script", "An example.")
parser:flag("-d --debug", "Enable debug output", false)
local args = parser:parse()

-- enable/disable debug functions
if args.debug then
    body.debug = print
else
    body.debug = function(m) end
end

-- test OK/KO icons
local test_ok = "✅"
local test_ko = "❌"

local test_cases = {
    {
        title = "Parsing a:b JSON body",
        prefix = "request.body.json",
        payload = [[{"a":"b"}]],
        b64 = false,
        expect = {
            values = {
                { key="request.body.json.name:a",  value="a" },
                { key="request.body.json.value:a", value="b" }
            }
        }
    },
    {
        title = "Parsing nested JSON body #1",
        prefix = "request.body.json",
        payload = [[{"a":{"b":"c"}}]],
        b64 = false,
        expect = {
            values = {
                { key="request.body.json.name:a.b",  value="a.b" },
                { key="request.body.json.value:a.b", value="c" }
            }
        }
    },
    {
        title = "Parsing nested JSON body #2",
        prefix = "request.body.json",
        payload = [[{
            "a": [
                {"b":"c"},
                "d",
                ["e"]
            ]
        }]],
        b64 = false,
        expect = {
            values = {
                { key="request.body.json.name:a.1.b",  value="a.1.b" },
                { key="request.body.json.value:a.1.b", value="c" },
                { key="request.body.json.name:a.2",  value="a.2" },
                { key="request.body.json.value:a.2", value="d" },
                { key="request.body.json.name:a.3.1",  value="a.3.1" },
                { key="request.body.json.value:a.3.1", value="e" }
            }
        }
    },
    {
        title = "Parsing a lot of nested array in JSON body",
        prefix = "request.body.json",
        payload = [[
            {
                "a": ]] .. string.rep("[", 1000).. [["foo"]] .. string.rep("]", 1000).. [[
            }
        ]],
        b64 = false,
        expect = {
            count = 2
        }
    }
}

for ktc,tc in ipairs(test_cases) do
    local start_time = os.time()
    print("\nTest case: " .. tc.title)
    
    if args.debug then print("\n--- Executing body:json() function ---") end
    
    tc.res = body:json(tc.prefix, tc.payload, tc.b64)
    
    if args.debug then print("--- End Executing ---\n") end

    if args.debug then
        print("--- Payload ---")
        print(inspect(tc.payload))
        print("--- Payload  ---\n")

        print("--- DUMP    ---")
        print(inspect(tc.res))
        print("--- DUMP    ---\n")
    end

    if tc.expect.values then
        for kv,v in ipairs(tc.expect.values) do
            for _,value in pairs(tc.res) do
                if value[v.key] then
                    if value[v.key] == v.value then
                        print("`- " .. test_ok .. " " .. v.key .. " matched with expected value: " .. v.value)
                        test_cases[ktc].expect.values[kv].matched = true
                    end
                end
            end
        end
    end

    if tc.expect.count then
        if tc.expect.count == #tc.res then
            print("`- " .. test_ok .. " " .. tc.expect.count .. " key-value pairs found")
        else
            print(test_ko .. " " .. tc.expect.count .. " key-value pairs expected but " .. #tc.res .. " found")
            assert(false)
        end
    end

    if tc.expect.values then
        for _,v in pairs(tc.expect.values) do
            if not v.matched then
                print(test_ko .. " " .. v.key .. " not found or did not match with expected value: " .. v.value)
                print("\n------------ DUMP ------------\n")
                print(inspect(tc.res))
                print("\n------------ DUMP ------------\n")
                assert(false)
            end
        end
    end

    local end_time = os.time()
    
    -- calc elapsed time
    local elapsed_time = (end_time - start_time)
    print("`- 🕙 Elapsed time: " .. elapsed_time .. " seconds")
end


