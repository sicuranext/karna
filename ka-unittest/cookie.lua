-- cookie_test.lua
local lu = require("luaunit")
local cjson = require("cjson")

-- Mock the dependencies
local ngx = {
    unescape_uri = function(str)
        return str:gsub("%%(%x%x)", function(h)
            return string.char(tonumber(h, 16))
        end)
    end
}
_G.ngx = ngx

local utils = {
    urldecode = function(self, str)
        if not str then return nil end
        str = str:gsub("+", " ")
        str = str:gsub("%%(%x%x)", function(h)
            return string.char(tonumber(h, 16))
        end)
        return str
    end
}

-- Create a mock module table with json method
local _M = {
    json = function(self, prefix, json_str, try_base64decode)
        local result = {}
        local decoded = cjson.decode(json_str)
        
        -- Flatten JSON for testing purposes
        local function flatten(obj, prefix)
            if type(obj) == "table" then
                for k, v in pairs(obj) do
                    if type(v) == "table" then
                        flatten(v, prefix .. "." .. k)
                    else
                        table.insert(result, prefix .. "." .. k .. "=" .. tostring(v))
                    end
                end
            else
                table.insert(result, tostring(obj))
            end
        end
        
        flatten(decoded, "")
        return result
    end
}

-- Mock require to return our module when cookie_module is requested
local original_require = require
_G.require = function(module_name)
    if module_name == "cookie_module" then
        -- Return a mock for the cookie module
        return _M
    else
        -- For all other modules, use the original require
        return original_require(module_name)
    end
end

-- Simulate loading the function definition into our mock module
-- In a real scenario, this would be loaded from a file
local cookie_module_code = [[
local _M = ...

---Parses and processes HTTP cookie strings into structured data.
---@param self table The module instance
---@param prefix string String prefix to prepend to keys in the returned table
---@param raw_string string The raw cookie string to parse
---@param try_base64decode_if_possible boolean Whether to attempt base64 decoding
---@return table values An array of tables where each table contains a single key-value pair. 
---Keys are formatted as either `prefix..".name:"..key:lower()` for cookie names 
---or `prefix..".value:"..key:lower()` for cookie values, where key is the cookie name.
---If a cookie value is JSON, multiple entries with the same key prefix but different values may be created.
---@note This function uses both utils:urldecode and ngx.unescape_uri for URL decoding
_M.cookie = function(self, prefix, raw_string, try_base64decode_if_possible)
    local values = {}
    local string_match = string.match
    local string_gsub = string.gsub

    -- check if raw_string is empty or nil
    if not raw_string or raw_string == "" then
        return values
    end

    local function split(input, delimiter)
        local result = {}
        for match in (input .. delimiter):gmatch("(.-)" .. delimiter) do
            table.insert(result, match)
        end
        return result
    end

    -- use utils:urldecode() to decode the raw_string
    raw_string = utils:urldecode(raw_string)

    local key_value_cookies = split(raw_string, ";")

    for _,pair in ipairs(key_value_cookies) do
        local key,value = string_match(pair, "([^=]+)=?(.*)")

        -- remove trailing and leading whitespaces from cookie name
        key = string_gsub(key, "^%s*(.-)%s*$", "%1")

        table.insert(values, {
            [prefix .. ".name:"..key:lower()] = key
        })

        -- if value starts with %7B%22 or %7b%22, then urldecode it
        -- since utils:urldecode decodes three times, I'm using ngx.unescape_uri here
        if string_match(value, "^%%7[bB]%%22") then
            value = ngx.unescape_uri(value)
        end

        -- using pcall as a "try-catch" alternative
        -- it doesn't need to catch any error, or return any feedback
        if string_match(value, "^[%{%[]") and pcall(cjson.decode,value) then
            local cookie_json_flat = self:json("request.cookie", value, try_base64decode_if_possible)
            for _,vv in pairs(cookie_json_flat) do
                table.insert(values, {
                    [prefix .. ".value:"..key:lower()] = vv
                })
            end
        else
            table.insert(values, {
                [prefix .. ".value:"..key:lower()] = value
            })
        end
    end

    return values
end

return _M
]]

-- Use load to execute the code and inject our _M table
local func = load(cookie_module_code)
func(_M)

-- Define the test cases
local TestCookie = {}

function TestCookie:setUp()
    -- This would normally be where we require the module
    self.module = require("cookie_module")
end

function TestCookie:testEmptyString()
    local result = self.module:cookie("test", "", false)
    lu.assertEquals(#result, 0, "Empty cookie string should return empty table")
end

function TestCookie:testNilInput()
    local result = self.module:cookie("test", nil, false)
    lu.assertEquals(#result, 0, "Nil cookie string should return empty table")
end

function TestCookie:testBasicCookie()
    local cookie_str = "name=value"
    local result = self.module:cookie("test", cookie_str, false)
    
    lu.assertEquals(#result, 2, "Basic cookie should result in 2 entries")
    lu.assertEquals(result[1]["test.name:name"], "name", "First entry should contain cookie name")
    lu.assertEquals(result[2]["test.value:name"], "value", "Second entry should contain cookie value")
end

function TestCookie:testMultipleCookies()
    local cookie_str = "name1=value1; name2=value2"
    local result = self.module:cookie("test", cookie_str, false)
    
    lu.assertEquals(#result, 4, "Two cookies should result in 4 entries")
    lu.assertEquals(result[1]["test.name:name1"], "name1")
    lu.assertEquals(result[2]["test.value:name1"], "value1")
    lu.assertEquals(result[3]["test.name:name2"], "name2")
    lu.assertEquals(result[4]["test.value:name2"], "value2")
end

function TestCookie:testCookieWithWhitespace()
    local cookie_str = "  name  =  value  "
    local result = self.module:cookie("test", cookie_str, false)
    
    lu.assertEquals(#result, 2, "Cookie with whitespace should result in 2 entries")
    lu.assertEquals(result[1]["test.name:name"], "name", "Whitespace should be trimmed from name")
    lu.assertEquals(result[2]["test.value:name"], "  value  ", "Whitespace in value should be preserved")
end

function TestCookie:testEncodedJsonCookie()
    local json_data = '{"key":"value","nested":{"prop":"val"}}'
    local encoded_json = "%7B%22key%22:%22value%22,%22nested%22:{%22prop%22:%22val%22}}"
    local cookie_str = "jsonData=" .. encoded_json
    
    local result = self.module:cookie("test", cookie_str, false)
    
    lu.assertIsTrue(#result > 2, "JSON cookie should result in multiple entries")
    lu.assertEquals(result[1]["test.name:jsondata"], "jsonData", "First entry should contain cookie name")
    -- Further assertions would depend on exact implementation of json flattening in self.module:json
end

function TestCookie:testCookieWithoutValue()
    local cookie_str = "flag="
    local result = self.module:cookie("test", cookie_str, false)
    
    lu.assertEquals(#result, 2, "Cookie without value should result in 2 entries")
    lu.assertEquals(result[1]["test.name:flag"], "flag")
    lu.assertEquals(result[2]["test.value:flag"], "")
end

-- Run the tests
os.exit(lu.LuaUnit.run())