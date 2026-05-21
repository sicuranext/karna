local full_path_lua_script = debug.getinfo(1, "S").source:sub(2)
local script_path = full_path_lua_script:match("(.*/)") or "./"
print("Script path: " .. script_path)
package.path = script_path..'?.lua;'..script_path..'../kong/plugins/karna/modules/?.lua;'..script_path..'/?.lua;' ..package.path

-- mock kong and ngx API
local kong_ngx_global = require "kong_ngx_global"
kong = kong_ngx_global.kong
ngx = kong_ngx_global.ngx
cjson = require "cjson"

local inspect   = require "inspect"
local body      = require "ka_body_parser"

local a = body:cookie("request.cookie", 'a=b;c={"foo":"bar"}', false)
print(inspect(a))

