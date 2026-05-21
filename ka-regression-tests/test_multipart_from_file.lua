local full_path_lua_script = debug.getinfo(1, "S").source:sub(2)
local script_path = full_path_lua_script:match("(.*/)") or "./"
package.path = script_path .. '?.lua;' .. script_path .. '../kong/plugins/karna/modules/?.lua;' .. package.path

local Multipart = require("multipart")
local rmultipart = require("multipart_resty")
local kamultipart = require("ka_multipart")
local inspect = require("inspect")

local argparse  = require "argparse"

-- parse script arguments
local parser = argparse("script", "An example.")
parser:option("-f --file", "file path with multipart body message", "kong")
parser:option("-t --type", "Lua multipart lib to use", "kong")
parser:option("-b --boundary", "Set a custom boundary (default xxx)", "xxx")
local args = parser:parse()

if args.debug then
    kamultipart.debug = true
end

--local body = t.test
-- load body from file

--[[
local body = "--xxx\r\n"..
"Content-Disposition: form-data; filename=a; filename=asd2.php\r\n"..
"Content-Type: text/plain\r\n"..
"\r\n"..
"asd\r\n"..
"--xxx--"
]]--

local body = "--xxx\r\n"..
"Content-Disposition: form-data; name=\"file\"; filename=\"asd.php\"; filename=\"asd2.php\"\r\n"..
"Content-Type: text/plain\r\n"..
"\r\n"..
"asd2\r\n"..
"--xxx--"

print("\n\n🚀 Start test")
print("--- PARSING BODY ---")
print("\27[32m" .. body .. "\27[0m")
print("--- END BODY -------\n\n")


if args.type == "kong" then
    local multipart_data = Multipart(body, "multipart/form-data; boundary="..args.boundary)
    print(inspect(multipart_data))
    local files = multipart_data:get_all_as_arrays()
    print(inspect(files))
end

if args.type == "resty" then
    local p, err = rmultipart.new(body, "multipart/form-data; boundary="..args.boundary)
    if not p then
        print("failed to create parser: ", err)
    end

    print(inspect(p))
    print("---")
    while true do
        local part_body, name, mime, filename = p:parse_part()
        if not part_body and not mime and not filename then
            print("--- end of parts ---")
            break
        end

        print("---\npart_body: ", tostring(part_body))
        print("name: ", tostring(name))
        print("mime: ", tostring(mime))
        print("filename: ", tostring(filename))
    end
end

