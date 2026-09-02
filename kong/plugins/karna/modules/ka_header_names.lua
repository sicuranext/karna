-- ka_header_names.lua
--
-- Request header NAMES, in the order the client sent them and with the
-- original casing, for the audit log (`request.header_names`). Names only,
-- never values: the values already live in `request.headers`.
--
-- Two capture modes, reported next to the list as `header_names_capture`:
--
--   "raw"        HTTP/1.x. Parsed from ngx.req.raw_header(true), i.e. the bytes
--                as they arrived on the wire, before Kong or any plugin
--                normalised or rewrote anything. Duplicate occurrences are
--                kept as separate entries, casing is untouched.
--
--   "normalized" HTTP/2 (ngx.req.raw_header is not available there) or any
--                failure of the raw path. Built from ngx.req.get_headers(0, true):
--                names lowercase, sorted alphabetically, repeated once per
--                value. HTTP/2 has no original casing, and a Lua hash has no
--                receive order, so sorting is the only honest deterministic
--                order. NOTE: this is the header set *as seen by Karna*, which
--                also contains headers injected by plugins that ran earlier in
--                the chain. The raw view never does.
--
-- Hard limits keep an adversarial request from inflating the log: at most
-- MAX_NAMES entries, each clipped to MAX_NAME_LEN bytes. Everything is pure
-- Lua over strings/tables so the parser is unit-testable without ngx.

local string_sub   = string.sub
local string_find  = string.find
local string_byte  = string.byte
local string_lower = string.lower
local table_sort   = table.sort

local _M = {}

_M.MAX_NAMES    = 128
_M.MAX_NAME_LEN = 256

-- Parse the raw header block (request line already stripped) into the ordered
-- list of names. Returns names, truncated.
--   * lines end with CRLF (LF alone is tolerated);
--   * a line starting with SP / HTAB is an obs-fold continuation, not a header;
--   * a line without ":" (or starting with ":") is not a header either.
function _M.parse_raw(raw, max_names, max_name_len)
    max_names    = max_names or _M.MAX_NAMES
    max_name_len = max_name_len or _M.MAX_NAME_LEN

    local names, n, truncated = {}, 0, false
    if type(raw) ~= "string" or raw == "" then
        return names, truncated
    end

    local pos, len = 1, #raw
    while pos <= len do
        local nl = string_find(raw, "\n", pos, true)
        local line
        if nl then
            line = string_sub(raw, pos, nl - 1)
            pos  = nl + 1
        else
            line = string_sub(raw, pos)
            pos  = len + 1
        end
        if string_byte(line, -1) == 13 then           -- trailing CR
            line = string_sub(line, 1, -2)
        end

        if line ~= "" then
            local first = string_byte(line, 1)
            if first ~= 32 and first ~= 9 then        -- not an obs-fold line
                local colon = string_find(line, ":", 1, true)
                if colon and colon > 1 then
                    if n >= max_names then
                        truncated = true
                        break
                    end
                    local name = string_sub(line, 1, colon - 1)
                    if #name > max_name_len then
                        name = string_sub(name, 1, max_name_len)
                    end
                    n = n + 1
                    names[n] = name
                end
            end
        end
    end

    return names, truncated
end

-- Normalized list from a headers table as returned by ngx.req.get_headers(0, true):
-- lowercase, sorted, one entry per value (a multi-value header is a table).
-- Returns names, truncated.
function _M.from_table(headers, max_names, max_name_len)
    max_names    = max_names or _M.MAX_NAMES
    max_name_len = max_name_len or _M.MAX_NAME_LEN

    local names, n = {}, 0
    if type(headers) ~= "table" then
        return names, false
    end

    for k, v in pairs(headers) do
        if type(k) == "string" then
            local count = 1
            if type(v) == "table" then
                count = #v
                if count < 1 then count = 1 end
            end
            local name = string_lower(k)
            if #name > max_name_len then
                name = string_sub(name, 1, max_name_len)
            end
            for _ = 1, count do
                n = n + 1
                names[n] = name
            end
        end
    end

    table_sort(names)

    local truncated = false
    if n > max_names then
        for i = n, max_names + 1, -1 do
            names[i] = nil
        end
        truncated = true
    end

    return names, truncated
end

-- Capture from the current request. `req` defaults to ngx.req and is
-- injectable for tests. Returns names, mode ("raw" | "normalized"), truncated.
-- Never throws: every ngx call is pcall'd; the worst case is an empty
-- normalized list.
function _M.capture(req, max_names, max_name_len)
    req = req or (ngx and ngx.req)
    if not req then
        return {}, "normalized", false
    end

    local ok, raw = pcall(req.raw_header, true)
    if ok and type(raw) == "string" then
        local names, truncated = _M.parse_raw(raw, max_names, max_name_len)
        return names, "raw", truncated
    end

    local ok2, headers = pcall(req.get_headers, 0, true)
    if not ok2 or type(headers) ~= "table" then
        return {}, "normalized", false
    end

    local names, truncated = _M.from_table(headers, max_names, max_name_len)
    return names, "normalized", truncated
end

return _M
