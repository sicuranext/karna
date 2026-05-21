-- Mock implementation of ngx.base64 for testing

local _M = {}

-- Basic base64 encoding function
-- Not intended to be cryptographically secure, just for testing
function _M.encode_base64(input)
    if not input then return nil end
    local b64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    local s = input
    return ((s:gsub('.', function(x) 
        local r, b = '', x:byte()
        for i = 8, 1, -1 do r = r .. (b % 2 ^ i - b % 2 ^ (i-1) > 0 and '1' or '0') end
        return r;
    end) .. '0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
        if (#x < 6) then return '' end
        local c = 0
        for i = 1, 6 do c = c + (x:sub(i,i) == '1' and 2 ^ (6-i) or 0) end
        return b64chars:sub(c+1, c+1)
    end) .. ({ '', '==', '=' })[#s % 3 + 1])
end

-- Basic base64 decoding function
-- Not intended to be cryptographically secure, just for testing
function _M.decode_base64(input)
    if not input then return nil end
    local b64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    local s = input:gsub('[^'..b64chars..'=]', '')
    return (s:gsub('.', function(x)
        if (x == '=') then return '' end
        local r, f = '', (b64chars:find(x) - 1)
        for i = 6, 1, -1 do r = r .. (f % 2 ^ i - f % 2 ^ (i-1) > 0 and '1' or '0') end
        return r;
    end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
        if (#x ~= 8) then return '' end
        local c = 0
        for i = 1, 8 do c = c + (x:sub(i,i) == '1' and 2 ^ (8-i) or 0) end
        return string.char(c)
    end))
end

-- Helper for URL-safe variants
function _M.encode_base64url(input)
    if not input then return nil end
    local encoded = _M.encode_base64(input)
    return encoded:gsub('+', '-'):gsub('/', '_'):gsub('=+$', '')
end

function _M.decode_base64url(input)
    if not input then return nil end
    local s = input:gsub('-', '+'):gsub('_', '/')
    -- Add padding if needed
    local padding = (4 - s:len() % 4) % 4
    s = s .. string.rep('=', padding)
    return _M.decode_base64(s)
end

return _M