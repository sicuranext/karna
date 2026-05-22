local _M = {}
local ngx                   = ngx
local kong                  = kong
local request_get_header    = kong.request.get_header or {}
local response_get_header   = kong.response.get_header or {}
local request_get_raw_body  = kong.request.get_raw_body or ""
local ngx_re_match          = ngx.re.match
local ngx_re_gmatch         = ngx.re.gmatch
local string_gsub           = string.gsub
local string_match          = string.match
local string_gmatch         = string.gmatch
local string_find           = string.find

local cjson                 = require "cjson"
local b64                   = require("ngx.base64")
local utils                 = require "kong.plugins.karna.ka_utils"
local multipart             = require "kong.plugins.karna.ka_multipart"

if not kong.mocked then
    _M.debug       = function(i) return end
    _M.inspect     = function(i) return end
    --_M.debug     = kong.log.debug
    --_M.inspect   = kong.log.inspect
end

---Parses and processes URL-encoded request bodies into structured data.
---@param self table The module instance
---@param prefix string String prefix to prepend to keys in the returned table
---@param raw_body string The raw URL-encoded body to parse
---@param try_base64decode_if_possible boolean Whether to attempt base64 decoding
---@return table values An array of tables where each table contains a single key-value pair
_M.urlencoded = function(self, prefix, raw_body, try_base64decode_if_possible)
    local values = {}

    local insert_new_value = function(label, value)
        --[[table.insert(values, {
            [label] = value
        })]]--
        if not values[label] then
            values[label] = value
        else
            kong.log.debug("Duplicated key found: " .. label)
            return nil, "duplicated key found"
        end
        return true, nil
    end

    if raw_body then
        -- extract all non "&" string sequences
        for keyval in string_gmatch(raw_body, "([^&]+)") do
            -- if there's at least 1 key=value, parse them
            local key,value = string_match(keyval, "([^=]+)=?(.*)")
            if key and value then
                -- URL-decode keys and values once. The URLENCODED body
                -- processor in ModSec urldecodes ARGS automatically — that's
                -- the canonical form rules see (regex/pmFromFile/libinjection
                -- all expect decoded ARGS, with `+` already converted to
                -- space, `%XX` already converted to the underlying byte). We
                -- mirror that here using ngx.unescape_uri (which handles `+`
                -- → space and `%XX` together). Skip on failure / no-op for
                -- values that don't contain `%` or `+`.
                if string_find(key, "[%%+]", 1, false) then
                    key = ngx.unescape_uri(key)
                end
                if string_find(value, "[%%+]", 1, false) then
                    value = ngx.unescape_uri(value)
                end

                local label_plain_name = prefix .. ".name:"..key:lower()
                local label_plain_value = prefix .. ".value:"..key:lower()

                local ok, err = insert_new_value(label_plain_name, key)
                if not ok then
                    kong.log.debug("Error inserting keyname: " .. err)
                    return nil, err
                end

                -- if value starts with %7B%22 or %7b%22, then urldecode it
                -- it could means it's a json value in key=value formatted string
                if string_match(value, "^%%7[bB]%%22") then
                    -- I'm using ngx.unescape_uri here because utils:urldecode decodes three times (to avoid bypass)
                    -- and ATM it's not the expected behavior for this case. It could change in the future.
                    value = ngx.unescape_uri(value)
                end

                if string_match(value, "^[%{%[]") and pcall(cjson.decode,value) then
                    local body_json_flat = self:json("request.body", value, try_base64decode_if_possible)

                    for _,vv in pairs(body_json_flat) do
                        local ok, err = insert_new_value(label_plain_value, vv)
                        if not ok then
                            kong.log.debug("Error inserting keyname: " .. err)
                            return nil, err
                        end
                    end
                else
                    local ok, err = insert_new_value(label_plain_value, value)
                    if not ok then
                        kong.log.debug("Error inserting keyname: " .. err)
                        return nil, err
                    end
                end

                if try_base64decode_if_possible then
                    local decoded_value, decoded_success = utils:base64_decode(value, true)
                    if decoded_success and decoded_value then
                        local ok, err = insert_new_value(label_plain_value.."_ka_b64_decoded", decoded_value)
                        if not ok then
                            kong.log.debug("Error inserting base64 decoded value: " .. err)
                            return nil, err
                        end
                    end
                end
            else
                local label_name = prefix .. ".name:"..keyval:lower()
                local label_value = prefix .. ".value:"..keyval:lower()

                -- if keyvan doesn't contains any = character
                if not string.match(keyval, "%=") then
                    local ok, err = insert_new_value(label_name, keyval)
                    if not ok then
                        kong.log.debug("Error inserting keyname: " .. err)
                        return nil, err
                    end
                end

                if try_base64decode_if_possible then
                    -- use utils:base64_decode() to decode the value
                    local decoded_value, decoded_success = utils:base64_decode(keyval, true)
                    if decoded_success and decoded_value then
                        local ok, err = insert_new_value(label_value.."_ka_b64_decoded", decoded_value)
                        if not ok then
                            kong.log.debug("Error inserting base64 decoded value: " .. err)
                            return nil, err
                        end
                    end
                end
            end
        end
        
        -- if len raw_querystring > 0 and character = not in raw_query_string
        if string.len(raw_body) > 0 and not string.match(raw_body, "=") then
            local label_name = prefix .. ".name:"..raw_body:lower()
            local label_value = prefix .. ".value:"..raw_body:lower()

            insert_new_value(label_name, raw_body)
            insert_new_value(label_value, "")

            if try_base64decode_if_possible then
                local decoded_value, decoded_success = utils:base64_decode(raw_body, true)
                if decoded_success and decoded_value then
                    local ok, err = insert_new_value(label_value.."_ka_b64_decoded", decoded_value)
                    if not ok then
                        kong.log.debug("Error inserting base64 decoded value: " .. err)
                        return nil, err
                    end
                end
            end
        end
    end -- end if body

    return values, nil
end

---Parses and processes JSON data into a flattened structure.
---@param self table The module instance
---@param prefix string String prefix to prepend to keys in the returned table
---@param raw_json string The raw JSON string to parse
---@param try_base64decode_if_possible boolean Whether to attempt base64 decoding of string values
---@return table values An array of tables where each table contains a single key-value pair.
---Keys are formatted as prefix + field path for values (e.g., "request.body.value:user.name")
---and as a corresponding name entry (e.g., "request.body.name:user.name").
---For string values where base64 decoding is requested and successful, additional entries with
---"_ka_b64_decoded" suffix are added.
---@note If JSON parsing fails, an empty table is returned
---@example
--- local json_values = _M:json("request.body", '{"user":{"name":"John","id":123}}', true)
--- -- Example return value:
--- -- {
--- --   { ["request.body.value:user.name"] = "John" },
--- --   { ["request.body.name:user.name"] = "user.name" },
--- --   { ["request.body.value:user.id"] = "123" },
--- --   { ["request.body.name:user.id"] = "user.id" }
--- -- }
_M.json = function(self, prefix, raw_json, try_base64decode_if_possible)
    local values = {}

    local status, body_json = pcall(cjson.decode, raw_json)
    if not status then
        self.debug("JSON: parsing failed")
        return nil, "json parsing failed"
    end

    local insert_new_value = function(label, value)
        --[[table.insert(values, {
            [label] = value
        })]]--
        if not values[label] then
            values[label] = value
        else
            kong.log.debug("Duplicated key found: " .. label)
            return nil, "duplicated key found"
        end

        return true, ""
    end

    local function flattenTable(t, parentKey, flatTable)
        flatTable = flatTable or {}
        parentKey = parentKey or prefix .. ".value:"

        if type(t) == "table" then
            for k, v in pairs(t) do
                local newKey = parentKey == "" and k or (parentKey .. "." .. k)
                local pattern_keyname_gsub = "^" .. string.gsub(prefix,"%.","%%.") .. "%.value%:%."

                if type(v) == "table" then
                    local ok, err = flattenTable(v, newKey, flatTable)
                    if not ok then
                        kong.log.debug("Error flattening table: " .. err)
                        return nil, err
                    end
                else
                    flatTable[newKey] = v
                    local keyname = string_gsub(newKey, pattern_keyname_gsub, prefix .. ".value:")

                    local ok, err = insert_new_value(keyname:lower(), tostring(v))
                    if not ok then
                        return nil, err
                    end

                    if try_base64decode_if_possible then
                        if type(v) == "string" then
                            local decoded_value, decoded_success = utils:base64_decode(v, true)
                            if decoded_success and decoded_value then

                                local ok, err = insert_new_value(keyname:lower().."_ka_b64_decoded", decoded_value)
                                if not ok then
                                    kong.log.debug("Error inserting base64 decoded value: " .. err)
                                    return nil, err
                                end
                            end
                        end
                    end

                    -- replace request.body.json: with request.body.json_key:
                    local keyname = string_gsub(newKey, pattern_keyname_gsub, prefix .. ".name:")
                    local keyvalue = string_gsub(newKey, pattern_keyname_gsub, "")

                    local ok, err = insert_new_value(keyname:lower(), tostring(keyvalue))
                    if not ok then
                        kong.log.debug("Error inserting keyname: " .. err)
                        return nil, err
                    end
                end
            end
        else
            flatTable[parentKey] = t
        end

        return true, nil
    end

    local ok, err = flattenTable(body_json)
    if not ok then
        kong.log.debug("Error flattening JSON: " .. err)
        return nil, err
    end

    return values, nil
end

_M.multipart = function(self, prefix, raw_body, try_base64decode_if_possible)
    local values = {}
    local content_type = request_get_header("content-type") or "multipart/form-data; boundary=boundary"

    self.debug("Trying to parse multipart body with content-type: " .. content_type)

    local multipart_data, mp_err = multipart:parse(raw_body, content_type)
    if multipart_data then
        for _,part in pairs(multipart_data) do
            --[[
            example:
                { {
                    body = "value1",
                    boundary = "xxx",
                    content_disposition = 'form-data; name="field1"',
                    content_length = 6,
                    headers = {
                    ["content-disposition"] = 'form-data; name="field1"'
                    },
                    name = "field1",
                    raw_headers = 'Content-Disposition: form-data; name="field1"'
                }, {
                    body = "value2",
                    boundary = "xxx",
                    content_disposition = 'form-data; name="field2"; filename="example.txt"',
                    content_length = 6,
                    content_type = "application/octet-stream",
                    extension = "txt",
                    filename = "example.txt",
                    headers = {
                    ["content-disposition"] = 'form-data; name="field2"; filename="example.txt"'
                    },
                    name = "field2",
                    raw_headers = 'Content-Disposition: form-data; name="field2"; filename="example.txt"'
                } }
            ]]--

            local name_lowercase = part.name:lower()

            table.insert(values, {
                [prefix .. ".name:"..name_lowercase] = part.name
            })
            table.insert(values, {
                [prefix .. ".value:"..name_lowercase] = part.body
            })

            if try_base64decode_if_possible then
                self.debug("         ` BASE64 try to decode enabled")
                -- replace + with - and / with _ to make it base64url compatible
                part.body = string_gsub(part.body, "+", "-")
                part.body = string_gsub(part.body, "/", "_")

                -- replace %3d with =
                part.body = string_gsub(part.body, "%%3d", "=")

                -- use pcall to catch errors
                local status, decoded = pcall(b64.decode_base64url, part.body)
                if status then
                    table.insert(values, {
                        [prefix .. ".value:"..name_lowercase.."_ka_b64_decoded"] = tostring(decoded)
                    })
                else
                    self.debug("         ` BASE64 decode failed on:" .. tostring(part.body))
                end
            end

            if part.filename then
                table.insert(values, {
                    [prefix .. ".filename:"..name_lowercase] = part.filename
                })
                if part.extension then
                    table.insert(values, {
                        [prefix .. ".extension:"..name_lowercase] = part.extension
                    })
                end
            end

            -- Per-part headers exposed in a Karna-native namespace. ModSec's
            -- equivalent is the TX-side-effect numbered bag set by the
            -- multipart body processor (TX:MULTIPART_HEADERS_CONTENT_TYPES_0,
            -- _1, _2, ...). Karna does not replicate that API smell: we expose
            -- the data as a clean multi-value variable instead, keyed by part
            -- name (and header name for the generic header.* shape). CRS rules
            -- that target the ModSec TX namespace get bridged through
            -- replace_condition overrides in coreruleset_fix.lua.
            for h_name, h_value in pairs(part.headers or {}) do
                local hn = h_name:lower()
                table.insert(values, {
                    [prefix .. ".part.header.value:" .. name_lowercase .. ":" .. hn] = h_value
                })
                table.insert(values, {
                    [prefix .. ".part.header.name:" .. name_lowercase .. ":" .. hn] = h_name
                })
                if hn == "content-type" then
                    -- Shortcut for the common case so rules don't have to
                    -- walk the part-header namespace just to read Content-Type.
                    table.insert(values, {
                        [prefix .. ".part.content_type:" .. name_lowercase] = h_value
                    })
                end
            end
        end
    end

    -- Propagate the parser rejection back to the caller so the engine can
    -- surface it as a block / audit event. The hardening flags in
    -- ka_multipart (check_duplicated_*, reject_filename_star, strict_crlf,
    -- require_closing_boundary, ...) only return `nil, err`; without
    -- propagation the rejection silently produces an empty values table
    -- and the request slips through.
    return values, mp_err
end

_M.old_multipart = function(self, prefix, raw_body, try_base64decode_if_possible)
    local values = {}
    local content_type = request_get_header("content-type") or "multipart/form-data; boundary=boundary"

    self.debug("Trying to parse multipart body with content-type: " .. content_type)

    local Multipart = require("multipart")
    local multipart_data = Multipart(raw_body, content_type)

    local t = multipart_data:get_all()
    self.debug("Multipart data by get_all():")
    self.inspect(t)
    for k,v in pairs(t) do
        self.debug("         ` key: " .. k)
        self.debug("         ` value: " .. v)
        table.insert(values, {
            [prefix .. ".name:"..k:lower()] = k
        })
        table.insert(values, {
            [prefix .. ".value:"..k:lower()] = v
        })

        if try_base64decode_if_possible then
            self.debug("         ` BASE64 try to decode enabled")
            -- replace + with - and / with _ to make it base64url compatible
            v = string_gsub(v, "+", "-")
            v = string_gsub(v, "/", "_")

            -- replace %3d with =
            v = string_gsub(v, "%%3d", "=")

            -- use pcall to catch errors
            local status, decoded = pcall(b64.decode_base64url, v)
            if status then
                table.insert(values, {
                    [prefix .. ".value:"..k:lower().."_ka_b64_decoded"] = tostring(decoded)
                })
            else
                self.debug("         ` BASE64 decode failed on:" .. tostring(v))
            end
        end
    end

    -- get all filenames from raw body
    local fname = ngx_re_gmatch(raw_body, 'Content-Disposition[^\r\n]+\\s+filename=["\']?(.*?)["\']?[\r\n]', "jo")
    local files = {}
    if fname then
        while true do
            local match = fname()
            if not match then
                break
            end
            table.insert(files, match[1])
        end
    end

    for f in pairs(files) do
        table.insert(values, {
            [prefix .. ".filename."..tostring(f)] = files[f]
        })
    end

    local pname = ngx_re_gmatch(raw_body, 'Content-Disposition[^\r\n]+\\s+name\\s*=\\s*["\'](.*?)["\']', "jo")
    if pname then
        local n = 1
        while true do
            local match = pname()
            if not match then
                break
            end
            table.insert(values, {
                [prefix .. ".name."..tostring(n)] = match[1]
            })
            n = n + 1
        end
    end

    local pname = ngx_re_gmatch(raw_body, 'Content-Disposition[^\r\n]+\\s+name\\s*=\\s*([^"\';\r\n\\s]+)', "jo")
    if pname then
        local n = 1
        while true do
            local match = pname()
            if not match then
                break
            end
            table.insert(values, {
                [prefix .. ".name."..tostring(n)] = match[1]
            })
            n = n + 1
        end
    end

    self.debug("Multipart data:")
    self.inspect(t)
    self.debug("Files:")
    self.inspect(files)

    -- TODO: maybe it worth to set here the body
    -- as parsed by the multipart library using
    -- kong.service.request.set_raw_body function
    -- in order to avoid type confusion between
    -- kong and the upstream service

    return values
end

_M.xml = function(self, prefix, raw_body, try_base64decode_if_possible)
    local values = {}
    local replace_nooe = function (prefix,nooe)
        -- replace %NOOE% with nooe in:
        -- request.body.xml.value.%NOOE%:
        -- request.body.xml.name.%NOOE%:
        -- request.body.xml.attr.value.%NOOE%:
        -- request.body.xml.attr.name.%NOOE%:
        local replaced_prefix = string_gsub(prefix, "^request%.body%.xml%.value%.%%NOOE%%:", "request.body.xml.value."..nooe..":")
        replaced_prefix = string_gsub(replaced_prefix, "^request%.body%.xml%.name%.%%NOOE%%:", "request.body.xml.name."..nooe..":")
        replaced_prefix = string_gsub(replaced_prefix, "^request%.body%.xml%.attr%.value%.%%NOOE%%:", "request.body.xml.attr.value."..nooe..":")
        replaced_prefix = string_gsub(replaced_prefix, "^request%.body%.xml%.attr%.name%.%%NOOE%%:", "request.body.xml.attr.name."..nooe..":")

        -- if not %%NOOE%% replace the number before :
        replaced_prefix = string_gsub(replaced_prefix, "^request%.body%.xml%.value%.[0-9]+:", "request.body.xml.value."..nooe..":")
        replaced_prefix = string_gsub(replaced_prefix, "^request%.body%.xml%.name%.[0-9]+:", "request.body.xml.name."..nooe..":")
        replaced_prefix = string_gsub(replaced_prefix, "^request%.body%.xml%.attr%.value%.[0-9]+:", "request.body.xml.attr.value."..nooe..":")
        replaced_prefix = string_gsub(replaced_prefix, "^request%.body%.xml%.attr%.name%.[0-9]+:", "request.body.xml.attr.name."..nooe..":")
        
        return replaced_prefix
    end
    local remove_prefix = function (prefix_value)
        local removed_prefix = string_gsub(prefix_value, "^request%.body%.xml%.value%.[0-9]+:", "")
        removed_prefix = string_gsub(removed_prefix, "^request%.body%.xml%.name%.[0-9]+:", "")
        removed_prefix = string_gsub(removed_prefix, "^request%.body%.xml%.attr%.value%.[0-9]+:", "")
        removed_prefix = string_gsub(removed_prefix, "^request%.body%.xml%.attr%.name%.[0-9]+:", "")
        return removed_prefix
    end

    local prefix_path_value = "request.body.xml.value.%NOOE%:"
    local prefix_path_name = "request.body.xml.name.%NOOE%:"
    local prefix_path_attr_value = "request.body.xml.attr.value.%NOOE%:"
    local prefix_path_attr_name = "request.body.xml.attr.name.%NOOE%:"
    local root_element = true
    local number_of_opened_elements = 0
    local SLAXML = require 'kong.plugins.karna.slaxml'
    
    local parser = SLAXML:parser {
        -- When "<foo" or <x:foo is seen
        startElement = function(name,nsURI,nsPrefix)
            number_of_opened_elements = number_of_opened_elements + 1
            self.debug("XML: startElement ".. tostring(number_of_opened_elements) .." name: " .. name)
            if nsURI then self.debug("startElement nsURI: " .. nsURI) end
            if nsPrefix then self.debug("startElement nsPrefix: " .. nsPrefix) end
            if root_element then
                prefix_path_value = replace_nooe(prefix_path_value, number_of_opened_elements) .. name
                prefix_path_name = replace_nooe(prefix_path_name, number_of_opened_elements) .. name
                prefix_path_attr_value = replace_nooe(prefix_path_attr_value, number_of_opened_elements) .. name
                prefix_path_attr_name = replace_nooe(prefix_path_attr_name, number_of_opened_elements) .. name
                root_element = false
            else
                prefix_path_value = replace_nooe(prefix_path_value, number_of_opened_elements) .. "." .. name
                prefix_path_name = replace_nooe(prefix_path_name, number_of_opened_elements) .. "." .. name
                prefix_path_attr_value = replace_nooe(prefix_path_attr_value, number_of_opened_elements) .. "." .. name
                prefix_path_attr_name = replace_nooe(prefix_path_attr_name, number_of_opened_elements) .. "." .. name
            end
        end,
        -- attribute found on current element
        attribute    = function(name,value,nsURI,nsPrefix)
            self.debug("attribute name: " .. name)
            self.debug("attribute value: " .. value)
            if nsURI then self.debug("attribute nsURI: " .. nsURI) end
            if nsPrefix then self.debug("attribute nsPrefix: " .. nsPrefix) end

            table.insert(values, {
                [prefix_path_attr_value.."."..name:lower()] = value
            })
            table.insert(values, {
                [prefix_path_attr_name.."."..name:lower()] = name
            })

            if try_base64decode_if_possible then
                -- replace + with - and / with _ to make it base64url compatible
                value = string_gsub(value, "+", "-")
                value = string_gsub(value, "/", "_")

                -- replace %3d with =
                value = string_gsub(value, "%%3d", "=")

                -- use pcall to catch errors
                local status, decoded = pcall(b64.decode_base64url, value)
                if status then
                    table.insert(values, {
                        [prefix_path_attr_value.."."..name:lower().."_ka_b64_decoded"] = tostring(decoded)
                    })
                end
            end
        end,
        -- When "</foo>" or </x:foo> or "/>" is seen
        closeElement = function(name,nsURI)
            self.debug("closeElement name: " .. name)
            if nsURI then self.debug("closeElement nsURI: " .. nsURI) end

            -- remove the last .<name> from all prefix_path
            prefix_path_value = string_gsub(prefix_path_value, "%.[^%.]+$", "")
            prefix_path_name = string_gsub(prefix_path_name, "%.[^%.]+$", "")
            prefix_path_attr_value = string_gsub(prefix_path_attr_value, "%.[^%.]+$", "")
            prefix_path_attr_name = string_gsub(prefix_path_attr_name, "%.[^%.]+$", "")
        end,
        -- text and CDATA nodes (cdata is true for cdata nodes)
        text         = function(text,cdata)
            self.debug("text text: " .. text)
            self.debug("text cdata: " .. tostring(cdata))

            table.insert(values, {
                [prefix_path_value .. ".value"] = text
            })
            table.insert(values, {
                [prefix_path_name .. ".name"] = remove_prefix(prefix_path_name)
            })

            if try_base64decode_if_possible then
                text = string_gsub(text, "+", "-")
                text = string_gsub(text, "/", "_")

                -- replace %3d with =
                text = string_gsub(text, "%%3d", "=")

                -- use pcall to catch errors
                local status, decoded = pcall(b64.decode_base64url, text)
                if status then
                    table.insert(values, {
                        [prefix_path_value .. ".value_ka_b64_decoded"] = tostring(decoded)
                    })
                end
            end
            if cdata then
                table.insert(values, {
                    [prefix_path_value .. ".cdata"] = tostring(cdata)
                })
                if try_base64decode_if_possible then
                    text = string_gsub(text, "+", "-")
                    text = string_gsub(text, "/", "_")

                    -- replace %3d with =
                    text = string_gsub(text, "%%3d", "=")

                    -- use pcall to catch errors
                    local status, decoded = pcall(b64.decode_base64url, text)
                    if status then
                        table.insert(values, {
                            [prefix_path_value .. ".cdata_ka_b64_decoded"] = tostring(decoded)
                        })
                    end
                end
            end
        end,
        -- comments
        comment      = function(content)
            self.debug("comment content: " .. content)
            --[[table.insert(values, {
                [prefix_path .. ".comment"] = content
            })]]--
        end,
        -- processing instructions e.g. "<?yes mon?>"
        pi           = function(target,content)
            self.debug("pi target: " .. target)
            self.debug("pi content: " .. content)
            --[[table.insert(values, {
                [prefix_path .. ".pi:"..target] = content
            })]]--
        end,
    }

    -- Ignore whitespace-only text nodes and strip leading/trailing whitespace from text
    -- (does not strip leading/trailing whitespace from CDATA)

    --parser:parse(raw_body,{stripWhitespace=true})

    if pcall(function() parser:parse(raw_body,{stripWhitespace=true}) end) then
        self.debug("XML: parsing successful")
    else
        self.debug("XML: parsing failed")
    end

    self.inspect(values)
    return values
end

_M.uncompress_response_body = function(self)
    local request_accept_encoding = request_get_header("accept-encoding")
    if not request_accept_encoding then
        request_accept_encoding = ""
    end

    local body = request_get_raw_body()
    if body then
        -- if body is gzipped, unzip it
        if string.find(request_accept_encoding, "gzip") then
            -- check if body contains gzip header
            if string.sub(body, 1, 2) == "\x1f\x8b" then
                local zlib = require "zlib"
                body = zlib.inflate()(body, "finish")
            end
        end
        return body
    end
end

_M.compress_response_body = function(self, body)
    local request_accept_encoding = request_get_header("accept-encoding")
    if not request_accept_encoding then
        request_accept_encoding = ""
    end

    if string.find(request_accept_encoding, "gzip") then
        if body then
            if string.sub(body, 1, 2) ~= "\x1f\x8b" then
                local zlib = require "zlib"

                local level = 5
                local windowSize = 15+16
                local deflate_stream = zlib.deflate(level, windowSize)
                local compressed_body = deflate_stream(body, "finish")
                return compressed_body
            end
        end
    end

    return body
end

_M.replace_response_body = function(self, regex, replace)
    local body = self:uncompress_response_body()

    -- transform response body
    if body then
        for k,v in pairs(self.response_body_pattern) do
            local res, n, err = ngx.re.gsub(body, regex, replace)
            if res then
                body = res
            end
        end
    end

    if body then
        body = self:compress_response_body(body)
        --ngx.arg[1] = body
        return body
    end
end

return _M
