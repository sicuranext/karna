package.path = './kong/plugins/karna/?.lua;' .. package.path

local inspect = require "inspect"

local allowed_bytes_number = {}
local condition_value_resolved = "10, 13, 32-126"
local string_to_match = "This is an english sentence."
local string_bytes_allowed = true

for w in string.gmatch(condition_value_resolved, "[0-9-]+") do
    if string.match(w, "-") then
        local start_range, end_range = string.match(w, "(%d+)-(%d+)")
        for i = start_range, end_range do
            -- remove .0 from i
            i = string.match(i, "(%d+)")
            table.insert(allowed_bytes_number, i)
        end
    else
        table.insert(allowed_bytes_number, w)
    end
end

local function is_byte_allowed(allowed_bytes_number, byte)
    for _,allowed_byte in ipairs(allowed_bytes_number) do
        if tostring(byte) == tostring(allowed_byte) then
            return true
        end
    end
    return false
end

for i = 1, #string_to_match do
    local byte = string.byte(string_to_match, i)
    if not is_byte_allowed(allowed_bytes_number, byte) then
        print("Byte not allowed: " .. tostring(byte) .. " at position: " .. tostring(i))
        string_bytes_allowed = false
        break
    end
end

print("String bytes allowed: " .. tostring(string_bytes_allowed))