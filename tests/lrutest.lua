print("start")

local function copy1(obj)
    if type(obj) ~= 'table' then return obj end
    local res = {}
    for k, v in pairs(obj) do res[copy1(k)] = copy1(v) end
    return res
end

local lrucache = require "resty.lrucache"
--local inspect = require "inspect"

local ka_rules, err = lrucache.new(10000)

ka_rules:set("ka_rules", {{pippo="pluto"}})

local obj = ka_rules:get("ka_rules")
local obj2 = copy1(obj)


print(obj2[1].pippo)
obj2[1].pippo = "foo"
print(obj2[1].pippo)

--local obj3 = ka_rules:get("ka_rules")
--inspect(obj2)
print(obj[1].pippo)
