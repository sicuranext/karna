local _M = {}

local inspect = require("inspect")

_M.debug = false
_M.check_missing_boundary = true
_M.check_wrong_boundary = true
_M.check_duplicated_header = true
_M.check_duplicated_content_disposition_param = true
_M.check_duplicated_content_disposition_header = true
_M.validate_header_name = true
_M.validate_boundary = true

function _M.get_boundary(self, content_type)
    local m = ngx.re.match(content_type, [[;\s*boundary\s*=\s*([0-9a-zA-Z'()+_,./:=?-]+)]], "joi")
    if m then
        return m[1] or nil
    end
    return nil
end

local function is_boundary_valid(boundary)
    local m = boundary:match("^[0-9a-zA-Z'()+_,./:=?-]+$")
    local l = #boundary
    return m and l >= 1 and l <= 70
end

local function is_header_name_valid(header_name)
    return header_name:match("^[a-zA-Z][a-zA-Z0-9-]*$")
end

function _M.parse(self, body, content_type)
    local t = {}

    -- get boundary string from content_type
    local boundary = self:get_boundary(content_type)
    if not boundary then
        if self.check_missing_boundary then
            return nil, "no boundary defined in Content-Type"
        end
    end

    if not is_boundary_valid(boundary) then
        if self.validate_boundary then
            return nil, "invalid boundary: " .. boundary
        end
    end

    local boundary_start = "^%-%-" .. boundary .. ""
    local boundary_end = "^%-%-" .. boundary .. "%-%-$"

    -- split body by lines by "\r\n"
    local start_collecting_headers = false
    local start_collecting_body = false
    local start_boundary_found = false
    local part_count = 0
    for line in body:gmatch("[^\n]+") do
        if line:match(boundary_end) then
            if self.debug then
                print("> END OF MULTIPART")
            end
            start_collecting_headers = false
            start_collecting_body = false
            break
        end

        if line:match(boundary_start) then
            if self.debug then print("> START OF PART") end
            start_boundary_found = true
            part_count = part_count + 1
            t[part_count] = {raw_headers="",body=""}
            start_collecting_headers = true
            start_collecting_body = false
        end

        if start_collecting_headers then
            if self.debug then print("> HEADER LINE: " .. line) end
            t[part_count].raw_headers = t[part_count].raw_headers .. line .. "\n"
        end
        if start_collecting_body then
            if self.debug then print("> BODY LINE: " .. line) end
            t[part_count].body = t[part_count].body .. line .. "\n"
        end


        if line:match("^\r$") then
            if self.debug then print("> END OF HEADERS / START BODY") end
            if not start_boundary_found then
                if self.check_wrong_boundary then
                    return nil, "boundary sent with Content-Type not found in body"
                end
            end
            start_collecting_headers = false
            start_collecting_body = true
        end
    end

    for i, part in ipairs(t) do
        -- remove last \r\n from body
        t[i].boundary = boundary
        t[i].body = t[i].body:sub(1, -3)
        t[i].content_length = #t[i].body

        -- remove last \r\n\r\n from raw_headers
        t[i].raw_headers = t[i].raw_headers:sub(1, -5)

        -- remove --<boundary>\r\n at the beginning of raw_headers
        t[i].raw_headers = string.gsub(t[i].raw_headers, "^%-%-" .. boundary .. "\r\n", "")

        -- split raw_headers by \r\n
        t[i].headers = {}
        for header in t[i].raw_headers:gmatch("[^\n]+") do
            local k, v = header:match("^([^:]+):%s*(.*)$")
            if k and v then
                -- validate header name
                if not is_header_name_valid(k) then
                    if self.validate_header_name then
                        return nil, "invalid header name: |" .. k:gsub("\r","\\r"):gsub("\n","\\n") .. "|"
                    end
                end

                local header_name_lowercase = k:lower()
                if not t[i].headers[header_name_lowercase] then
                    local m = v:match("^([^\r\n]+)")
                    if m then
                        t[i].headers[header_name_lowercase] = m
                    end
                else
                    if self.check_duplicated_header then
                        return nil, "duplicated header: " .. header_name_lowercase
                    end
                end

                -- parse key=value pairs in v
                local key_values = {}
                if header_name_lowercase == "content-disposition" then
                    if not t[i].content_disposition then
                        t[i].content_disposition = v
                        local m_params = v:match("form%-data%;%s*(.+)")
                        -- split m_params[1] by ;
                        if m_params then
                            local m = m_params:gmatch("(%S+)%=['\"]?([^;\r\n\"]+)['\"]?")
                            -- parse key=value pairs
                            while true do
                                local key, value = m()
                                if not key then
                                    break
                                end
                                local key_lowercase = key:lower()
                                if not t[i][key_lowercase] then
                                    t[i][key_lowercase] = value
                                else
                                    if self.check_duplicated_content_disposition_param then
                                        return nil, "duplicated content-disposition parameter: " .. key_lowercase
                                    end
                                end
                            end
                        end
                    else
                        if self.check_duplicated_content_disposition_header then
                            return nil, "duplicated content-disposition header"
                        end
                    end
                end

                if k == "Content-Type" then
                    -- split v by ;
                    local m = v:match("([^;]+)")
                    -- parse key=value pairs
                    if m then
                        t[i].content_type = m
                    end
                end
            end
        end

        -- if filename but not content-type, set content-type to application/octet-stream
        if t[i].filename and not t[i].content_type then
            t[i].content_type = "application/octet-stream"
        end

        if not t[i].content_disposition then
            t[i] = nil
        end
    end

    -- split each raw_headers parts by \r\n

    --print(inspect(t))
    return t, nil
end

function _M.table_to_multipart(self, t)
    -- generate boundary string: "KarnaBoundary" + timestamp + random
    local boundary = "KarnaBoundary"..tostring(ngx.now()):gsub("%.","")..string.sub(tostring({}), 10)
    local multipart_message = ""

    for _,part in ipairs(t) do
        multipart_message = multipart_message .. "--"..boundary.."\r\n"
        for k,v in pairs(part.headers) do
            multipart_message = multipart_message .. k .. ": " .. v .. "\r\n"
        end
        multipart_message = multipart_message .. "\r\n" .. part.body .. "\r\n"
    end

    multipart_message = multipart_message .. "--"..boundary.."--"
    return multipart_message, nil
end

return _M
