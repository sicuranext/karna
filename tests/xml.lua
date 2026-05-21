--local cjson                 = require "cjson"
local xml2lua               = require "xml2lua"
local handler               = require("xmlhandler.tree")
local inspect               = require "inspect"

local xml = function(prefix, raw_body)
    local values = {}
    local parser = xml2lua.parser(handler)
    parser:parse(raw_body)

    local flatTable = handler.root

    local function flattenTable(t, parentKey, flatTable)
        flatTable = flatTable or {}
        parentKey = parentKey or prefix .. ".value:"

        if type(t) == "table" then
            for k, v in pairs(t) do
                local newKey = parentKey == "" and k or (parentKey .. "." .. k)

                if type(v) == "table" then
                    flattenTable(v, newKey, flatTable)
                else
                    flatTable[newKey] = v
                    local keyname = string_gsub(newKey, "^" .. string.gsub(prefix,"%.","%%.") .. "%.value%:%.", prefix .. ".value:")
                    table.insert(values, {
                        [keyname:lower()] = tostring(v)
                    })

                    -- replace request.body.json: with request.body.json_key:
                    local keyname = string_gsub(newKey, "^" .. string.gsub(prefix,"%.","%%.") .. "%.value%:%.", prefix .. ".name:")
                    local keyvalue = string_gsub(newKey, "^" .. string.gsub(prefix,"%.","%%.") .. "%.value%:%.", "")
                    table.insert(values, {
                        [keyname:lower()] = tostring(keyvalue)
                    })

                end
            end
        else
            flatTable[parentKey] = t
        end
        return values
    end

    return flattenTable(flatTable)
end

local xml_raw = [[
<people>
  <person type="natural">
    <name>Manoel</name>
    <city>Palmas-TO</city>
  </person>
  <person type="legal">
    <name>University of Brasília</name>
    <city>Brasília-DF</city>
  </person>
</people>
]]

print(inspect(xml("request.body.xml", xml_raw)))