package.path = './kong/plugins/karna/?.lua;' .. package.path
local inspect = require "inspect"

local urlencoded = function(prefix, raw_body)
    local values = {}

    if raw_body then
        for keyval in string.gmatch(raw_body, "([^&]+)") do
            local key,value = string.match(keyval, "([^=]+)=?(.*)")
            if key and value then
                table.insert(values, {
                    [prefix .. ".name:"..key:lower()] = key
                })
                table.insert(values, {
                    [prefix .. ".value:"..key:lower()] = value
                })
            end
        end
        -- if len raw_querystring > 0 and character = not in raw_query_string
        if string.len(raw_body) > 0 and not string.match(raw_body, "=") then
            table.insert(values, {
                [prefix..".name:"..raw_body:lower()] = raw_body
            })
            table.insert(values, {
                [prefix..".value:"..raw_body:lower()] = ""
            })
        end
    end -- end if body

    return values
end

local b = urlencoded("test", "cmd=garb=adduse[r];$garb pizza\n")
print(inspect(b))

local b = urlencoded("test", "foo=bar&pippo=1&&pluto&cmd=garb=adduse[r];$garb pizza\n")
print(inspect(b))

local b = urlencoded("test", "foo=bar&pippo=1&&pluto=&cmd=garb=adduse[r];$garb pizza\n")
print(inspect(b))
