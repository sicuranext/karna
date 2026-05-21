
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
        title = "Parsing 3 key-value pairs from-urlencoded body",
        prefix = "request.body.urlencode",
        payload = [[param1=foo&param2=bar&param3=foobar]],
        b64 = false,
        expect = {
            values = {
                { key="request.body.urlencode.name:param1",  value="param1" },
                { key="request.body.urlencode.value:param1", value="foo" },
                { key="request.body.urlencode.name:param2",  value="param2" },
                { key="request.body.urlencode.value:param2", value="bar" },
                { key="request.body.urlencode.name:param3",  value="param3" },
                { key="request.body.urlencode.value:param3", value="foobar" }
            }
        }
    },
    {
        title = "Parsing 3 key-value pairs from-urlencoded body with base64 encoded values",
        prefix = "request.body.urlencode",
        payload = [[param1=Zm9v&param2=YmFy&param3=Zm9vYmFy]],
        b64 = true,
        expect = {
            values = {
                { key="request.body.urlencode.name:param1",  value="param1" },
                { key="request.body.urlencode.value:param1_ka_b64_decoded", value="foo" },
                { key="request.body.urlencode.name:param2",  value="param2" },
                { key="request.body.urlencode.value:param2_ka_b64_decoded", value="bar" },
                { key="request.body.urlencode.name:param3",  value="param3" },
                { key="request.body.urlencode.value:param3_ka_b64_decoded", value="foobar" }
            }
        }
    },
    {
        title = "Parsing 3 key-value pairs from-urlencoded body with empty value",
        prefix = "request.body.urlencode",
        payload = [[param1=&param2=bar&param3=foobar]],
        b64 = false,
        expect = {
            values = {
                { key="request.body.urlencode.name:param1",  value="param1" },
                { key="request.body.urlencode.value:param1", value="" },
                { key="request.body.urlencode.name:param2",  value="param2" },
                { key="request.body.urlencode.value:param2", value="bar" },
                { key="request.body.urlencode.name:param3",  value="param3" },
                { key="request.body.urlencode.value:param3", value="foobar" }
            }
        }
    },
    {
        title = "Parsing 3 key-value pairs from-urlencoded body with empty value and empty name",
        prefix = "request.body.urlencode",
        payload = [[=foo&param2=bar&param3=foobar]],
        b64 = false,
        expect = {
            values = {
                { key="request.body.urlencode.name:param2",  value="param2" },
                { key="request.body.urlencode.value:param2", value="bar" },
                { key="request.body.urlencode.name:param3",  value="param3" },
                { key="request.body.urlencode.value:param3", value="foobar" }
            },
            count = 6
        }
    },
    {
        title = "Parsing 3 key-value pairs from-urlencoded body with multiple = characters",
        prefix = "request.body.urlencode",
        payload = [[param1=foo&param2======bar&param3=foobar]],
        b64 = false,
        expect = {
            values = {
                { key="request.body.urlencode.name:param1",  value="param1" },
                { key="request.body.urlencode.value:param1", value="foo" },
                { key="request.body.urlencode.name:param2",  value="param2" },
                { key="request.body.urlencode.value:param2", value="=====bar" },
                { key="request.body.urlencode.name:param3",  value="param3" },
                { key="request.body.urlencode.value:param3", value="foobar" }
            }
        }
    },
    {
        title = "Parsing 3 key-value pairs from-urlencoded body with multiple = and & characters sequences",
        prefix = "request.body.urlencode",
        payload = [[param1=foo&param2==&=&=&=&=bar&param3=foobar]],
        b64 = false,
        expect = {
            values = {
                { key="request.body.urlencode.name:param1",  value="param1" },
                { key="request.body.urlencode.value:param1", value="foo" },
                { key="request.body.urlencode.name:param2",  value="param2" },
                { key="request.body.urlencode.value:param2", value="=" },
                { key="request.body.urlencode.name:param3",  value="param3" },
                { key="request.body.urlencode.value:param3", value="foobar" }
            }
        }
    },
    {
        title = "Parsing 3 key-value pairs from-urlencoded body with utf8 characters",
        prefix = "request.body.urlencode",
        payload = [[param1=foo&param2=👍&param3=foobar]],
        b64 = false,
        expect = {
            values = {
                { key="request.body.urlencode.name:param1",  value="param1" },
                { key="request.body.urlencode.value:param1", value="foo" },
                { key="request.body.urlencode.name:param2",  value="param2" },
                { key="request.body.urlencode.value:param2", value="👍" },
                { key="request.body.urlencode.name:param3",  value="param3" },
                { key="request.body.urlencode.value:param3", value="foobar" }
            }
        }
    },
    {
        title = "Parsing duplicated key values",
        prefix = "request.body.urlencode",
        payload = [[p=foo&p=bar&p=foobar]],
        b64 = false,
        expect = {
            values = {
                { key="request.body.urlencode.name:p",  value="p" },
                { key="request.body.urlencode.value:p", value="foo" },
                { key="request.body.urlencode.value:p", value="bar" },
                { key="request.body.urlencode.value:p", value="foobar" }
            },
            count = 6
        }
    },
    {
        title = "Parsing array syntax key values",
        prefix = "request.body.urlencode",
        payload = [[a[1]=foo&a[2]=bar]],
        b64 = false,
        expect = {
            values = {
                { key="request.body.urlencode.name:a[1]",  value="a[1]" },
                { key="request.body.urlencode.value:a[1]", value="foo" },
                { key="request.body.urlencode.name:a[2]",  value="a[2]" },
                { key="request.body.urlencode.value:a[2]", value="bar" }
            },
            count = 4
        }
    },
    {
        title = "Parsing JSON string in value (encoded)",
        prefix = "request.body.urlencode",
        payload = [[foo=%7b%22a%22:%22b%22%7d]],
        b64 = false,
        expect = {
            values = {
                { key="request.body.urlencode.name:foo",  value="foo" },
                --{ key="request.body.urlencode.value:foo", value="%7b%22a%22:%22b%22%7d" },
                --{ key="request.body.urlencode.name:a[2]",  value="a[2]" },
                --{ key="request.body.urlencode.value:a[2]", value="bar" }
            },
            count = 3
        }
    }
}

for ktc,tc in ipairs(test_cases) do
    print("\nTest case: " .. tc.title)
    if args.debug then
        print("\n--- Executing body:urlencoded() function ---")
    end
    tc.res = body:urlencoded(tc.prefix, tc.payload, tc.b64)
    if args.debug then
        print("--- End Executing ---\n")
    end

    if args.debug then
        print("--- Payload ---")
        print(inspect(tc.payload))
        print("--- Payload  ---\n")

        print("--- DUMP    ---")
        print(inspect(tc.res))
        print("--- DUMP    ---\n")
    end
    for kv,v in ipairs(tc.expect.values) do
        for _,value in pairs(tc.res) do
            if value[v.key] then
                if value[v.key] == v.value then
                    print("`- " .. test_ok .. " " .. v.key .. " matched with expected value: " .. v.value)
                    test_cases[ktc].expect.values[kv].matched = true
                --[[else
                    print(test_ko .. " " .. v.key .. " not matched with expected value: " .. v.value)
                    
                    assert(false)]]--
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




