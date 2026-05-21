
--[[
    Get full path of this script and add it to package.path
]]--
local full_path_lua_script = debug.getinfo(1, "S").source:sub(2)
local script_path = full_path_lua_script:match("(.*/)") or "./"
package.path = script_path..'?.lua;'..script_path .. '../kong/plugins/karna/modules/?.lua;' .. package.path

-- mock kong and ngx API
--local kong_ngx_global = require "kong_ngx_global"
--kong = kong_ngx_global.kong
--ngx = kong_ngx_global.ngx

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
    body.inspect = function(m) print(inspect(m)) end
else
    body.debug = function(m) end
    body.inspect = function(m) end
end

-- test OK/KO icons
local test_ok = "✅"
local test_ko = "❌"

local test_cases = {
    {
        title = "test",
        prefix = "request.body.multipart",
        payload = "--boundary\r\nContent-Disposition: form-data; name=\"field1\"\r\n\r\nvalue1\r\n--boundary\r\nContent-Disposition: form-data; name=\"field2\"; filename=\"example.txt\"\r\n\r\nvalue2\r\n--boundary--",
        b64 = false,
        expect = {
            values = {
                { key="request.body.multipart.name:field1",  value="field1" },
                { key="request.body.multipart.value:field1", value="value1" },
                { key="request.body.multipart.name:field2",  value="field2" },
                { key="request.body.multipart.value:field2", value="value2" },
                { key="request.body.multipart.filename:field2", value="example.txt" },
                { key="request.body.multipart.extension:field2", value="txt" }
            }
        }
    }
}

for ktc,tc in ipairs(test_cases) do
    print("\nTest case: " .. tc.title)
    if args.debug then
        print("\n--- Executing body:multipart() function ---")
    end
    tc.res = body:multipart(tc.prefix, tc.payload, tc.b64)
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




