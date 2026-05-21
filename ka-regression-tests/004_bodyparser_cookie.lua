
--[[
    Get full path of this script and add it to package.path
]]--
local full_path_lua_script = debug.getinfo(1, "S").source:sub(2)
local script_path = full_path_lua_script:match("(.*/)") or "./"
package.path = script_path..'?.lua;'..script_path..'../kong/plugins/karna/modules/?.lua;'..script_path..'/?.lua;' ..package.path

-- mock kong and ngx API
--local kong_ngx_global = require "kong_ngx_global"
--kong = kong_ngx_global.kong
--ngx = kong_ngx_global.ngx
cjson = require "cjson"

local test_helper = require "test_helper"
local body = test_helper.load_body_parser()

local inspect   = require "inspect"
--local body      = require "ka_body_parser"
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
        title = "Parsing standard cookie key=value",
        prefix = "request.cookie",
        payload = [[_ga=GA1.1.1234567.123456; wp-settings-3=editor=tinymce&hidetb=1&libraryContent=browse; wp-settings-time-3=1709142410]],
        b64 = false,
        expect = function(res)
            if 
                res[1]["request.cookie.name:_ga"] == "_ga" and 
                res[2]["request.cookie.value:_ga"] == "GA1.1.1234567.123456"
            then
                print(test_ok .. " Test passed: " .. res[1]["request.cookie.name:_ga"] .. " / " .. res[1]["request.cookie.value:_ga"])
            else
                print(test_ko .. " Test failed")
                print(inspect(res[1]))
                print(inspect(res[2]))
            end

            if
                res[3]["request.cookie.name:wp-settings-3"] == "wp-settings-3" and
                res[4]["request.cookie.value:wp-settings-3"] == "editor=tinymce&hidetb=1&libraryContent=browse"
            then
                print(test_ok .. "Test passed" .. res[3]["request.cookie.name:wp-settings-3"] .. " / " .. res[4]["request.cookie.value:wp-settings-3"])
            else
                print(test_ko .. "Test failed")
                print(inspect(res[3]))
                print(inspect(res[4]))
            end

        end
    },
    {
        title = "Parsing cookie key=value with a JSON string instead of value",
        prefix = "request.cookie",
        payload = [[_iub_cs-10334012={"timestamp":"2024-05-11T17:22:51.606Z","version":"1.60.1","purposes":{"1":true,"2":true,"3":true,"4":true,"5":true},"id":10334012,"cons":{"rand":"34d7b9"}}]],
        b64 = false,
        expect = {
            values = {
                { key="request.cookie.value:_iub_cs-10334012",  value={ key="request.cookie.value:id", value="10334012" } }
            }
        }
    }
}

for ktc,tc in ipairs(test_cases) do
    print("\nTest case: " .. tc.title)
    local res = body:cookie(tc.prefix, tc.payload, tc.b64)
    print(inspect(res))
    tc.expect(res)
end




