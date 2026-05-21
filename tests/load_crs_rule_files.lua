package.path = './kong/plugins/karna/modules/?.lua;' .. package.path

local seclang = require "seclang"
local inspect = require "inspect"
local rules = {}

seclang.crs_path = "/opt/coreruleset/rules/"

local content_to_parse = ""
local crs_files_contents = seclang.collect_crs_conf_files()

-- order crs_files_contents by key
--[[
local ordered_crs_files_contents = {}
for filename,content in pairs(crs_files_contents) do
    table.insert(ordered_crs_files_contents, {filename=filename, content=content})
end
table.sort(ordered_crs_files_contents, function(a,b) return a.filename < b.filename end)

local table_content_to_parse = {}
for _,crsf in pairs(ordered_crs_files_contents) do
    --print(inspect(crsf.filename))
    print("Collecting content from file: " .. crsf.filename)
    content_to_parse = content_to_parse .. crsf.content
    print("@@@> Content Length: " .. tostring(#crsf.content))
end
print("@@@@@@@@@ Content To Parse Length: " .. tostring(#content_to_parse))
]]--

local parsed_rules = {}
for filename,content in pairs(crs_files_contents) do
    print("Parsing content from file: " .. filename)
    parsed_rules = seclang.parse(content)
end

local rules_count = 0
for rule_id,rule in pairs(parsed_rules) do
    print("Rule ID: " .. rule_id)
    rules_count = rules_count + 1
    rules[rule_id] = rule
end
print("Rules Count: " .. tostring(rules_count))
--rules = seclang.parse(content_to_parse)

local rules_total_count = 0
for rule_id,rule in pairs(rules) do
    rules_total_count = rules_total_count + 1
end
print("Rules Total Count: " .. tostring(rules_total_count))

print(inspect(rules))
