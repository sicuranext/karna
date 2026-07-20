local re_match  = ngx.re.match
local _M = {}

-- Escape Lua pattern metacharacters in an arbitrary string so it can be
-- concatenated into a Lua pattern without changing its meaning. Lua's
-- pattern metacharacters are: ( ) . % + - * ? [ ] ^ $
-- Multipart boundaries legitimately contain `-` (very common: 30+ dashes
-- in `---------------------------627652292512397580456702590`) plus
-- `( ) + , . ? = _` (allowed by RFC 2046 + the boundary validator below).
-- Without escaping, `-` becomes "0+ lazy quantifier" and the boundary
-- pattern explodes into catastrophic backtracking — Lua-native patterns
-- are NOT capped by `lua_regex_match_limit` (that's PCRE only), so the
-- worker spins forever.
local function escape_lua_pattern(s)
    return (s:gsub("[%(%)%.%%%+%-%*%?%[%]%^%$]", "%%%1"))
end

-- Tokenize Content-Disposition params into segments split by `;`, but
-- treating `"..."` substrings as atomic so a `;` inside a quoted value
-- doesn't split the segment. Without this, the payload
--   name="evil;.txt"
-- splits into  name="evil  +  .txt"  — Karna sees a truncated `name`
-- while an RFC 7230-compliant backend (PHP/Flask/Busboy/Gunicorn) sees
-- the full `evil;.txt`. That divergence is one of the multipart bypass
-- classes documented at
-- https://blog.sicuranext.com/breaking-down-multipart-parsers-validation-bypass/
-- Backslash-escaped quotes inside the quoted string (`\"`) are NOT yet
-- handled here — a `name="a\";evil"` payload can still desync. Tracked
-- as residual gap in the project memory.
local function tokenize_cd_params(s)
    local segments = {}
    local buf = {}
    local inside_quotes = false
    for i = 1, #s do
        local c = s:sub(i, i)
        if c == '"' then
            inside_quotes = not inside_quotes
            buf[#buf + 1] = c
        elseif c == ";" and not inside_quotes then
            segments[#segments + 1] = table.concat(buf)
            buf = {}
        else
            buf[#buf + 1] = c
        end
    end
    if #buf > 0 then
        segments[#segments + 1] = table.concat(buf)
    end
    return segments
end

_M.debug = false
_M.check_missing_boundary = true
_M.check_wrong_boundary = true
_M.check_duplicated_header = true
_M.check_duplicated_content_disposition_param = true
_M.check_duplicated_content_disposition_header = true
_M.check_content_disposition = true
_M.check_name_in_content_disposition = true
_M.validate_header_name = true
_M.validate_boundary = true
_M.validate_param_value = true
-- Reject RFC 5987 / RFC 6266 ext-parameter (`filename*=`, `name*=`, ...)
-- in request bodies. Backends process them (and URL-decode `%XX`) while
-- most WAFs inspect the bare `filename=`. Closes Bypass #5 / #5a.
_M.reject_filename_star = true
-- Require RFC 2046 quoted-string form for CD parameter values. When on,
-- `filename=backdoor.php` (unquoted) is rejected. Closes Bypass #3 / #8.
_M.require_quoted_params = true
-- Require strict CRLF line separators on the multipart FRAMING (boundary
-- lines, part headers, the header/body separator). A bare LF or bare CR in
-- framing is a desync bypass class (a lenient backend accepts it and parses
-- a different structure than a strict WAF). Closes Bypass #2. Inside opaque
-- part content a bare LF / CR is data, not framing, so it's kept verbatim —
-- binary uploads (an image carries thousands of raw 0x0D / 0x0A bytes) are
-- not rejected.
_M.strict_crlf = true
-- Require the explicit closing `--<boundary>--` line. PHP accepts
-- incomplete bodies; strict WAFs must reject. Closes Bypass #4.
_M.require_closing_boundary = true
-- Reject a part whose boundary is glued directly onto the headers terminator
-- with no body section: `...name="x"\r\n\r\n--boundary` instead of the
-- well-formed `...name="x"\r\n\r\n\r\n--boundary`. RFC 2046 delimits a part
-- body with `CRLF--boundary`, so even an empty field carries its body's
-- trailing CRLF — a missing one is malformed and parsed differently by the
-- backend (which reads the following boundary line as this part's body) than
-- by a line-based WAF (the multipart empty-part desync; terjanq WAF-bypass
-- #3). Legitimate empty fields (curl / browsers emit the full `\r\n\r\n\r\n`
-- form) are unaffected.
_M.reject_bodyless_part = true

_M.get_boundary = function(self, content_type)
    local m = re_match(content_type, [[;\s*boundary\s*=\s*([0-9a-zA-Z'()+_,./:=?-]+)]], "joi")
    if m then
        return m[1] or nil
    end
    return nil
end

_M.is_boundary_valid = function(self, boundary)
    local m = boundary:match("^[0-9a-zA-Z'()+_,./:=?-]+$")
    local l = #boundary
    return m and l >= 1 and l <= 70
end

function _M.is_header_name_valid(self, header_name)
    if header_name:match("^[a-zA-Z][a-zA-Z0-9-]*$") then
        if header_name == "content-disposition" or header_name == "content-type" then
            return true
        end
    end

    return false
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

    if not self:is_boundary_valid(boundary) then
        if self.validate_boundary then
            return nil, "invalid boundary: " .. boundary
        end
    end

    local boundary_escaped = escape_lua_pattern(boundary)
    local boundary_start = "^%-%-" .. boundary_escaped .. ""
    local boundary_end = "^%-%-" .. boundary_escaped .. "%-%-$"

    -- Gap #4: strict CRLF. RFC 2046 mandates `\r\n` on framing; lenient
    -- backends accept a bare `\n` (or a bare `\r`) and split the body
    -- differently from a strict WAF — a documented desync class.
    --
    -- Neither bare LF nor bare CR is scanned body-wide. A body-wide bare-CR
    -- scan used to live here, but it rejected every real binary upload: a
    -- `\r` (0x0D) byte not followed by `\n` is ordinary data inside opaque
    -- part content (a ~1 MB image carries thousands of them), not a desync,
    -- so an image POST to e.g. Ghost's admin upload endpoint was blocked with
    -- "bare CR found in body". The strict-CRLF requirement only matters on the
    -- FRAMING — boundary lines, part headers, the header/body separator, and
    -- the `\r\n` preceding every delimiter — where a lone LF or CR really can
    -- make a lenient backend see a different structure. So both are enforced
    -- inside the parse loop below, scoped to framing; inside a part body they
    -- are kept verbatim (the loop splits on `\n` only, so an interior `\r` is
    -- preserved rather than dropped — that is what keeps a bare CR hidden in a
    -- non-file field value inside ARGS where it still gets inspected).

    -- Normalise trailing CRLF. The closing `--<boundary>--` line is
    -- often sent without a trailing `\r\n` (RFC 2046 allows it), but
    -- the gmatch below yields only lines ending in `\r?\n`. Append one
    -- if missing so the closing boundary still surfaces as a line.
    if body:sub(-2) ~= "\r\n" then
        body = body .. "\r\n"
    end

    -- Split the body into lines on `\n`. We capture everything up to the next
    -- `\n` (INCLUDING any `\r`), then peel a single trailing `\r` to recover
    -- the logical line and whether it ended in CRLF (`cr`). Splitting on `\n`
    -- only — not on `\r\n` — means an interior bare `\r` stays inside `line`
    -- instead of being silently dropped, so a bare CR hidden in a non-file
    -- field value survives into ARGS and gets inspected.
    local start_collecting_headers = false
    local start_collecting_body = false
    local start_boundary_found = false
    local end_boundary_found = false
    local part_count = 0
    -- prev_cr: did the previous line end in CRLF ("\r") or bare LF ("")?
    -- first_line guards the opening boundary, which has no preceding line.
    local prev_cr = "\r"
    local first_line = true
    for raw in body:gmatch("([^\n]*)\n") do
        local cr, line
        if #raw > 0 and raw:byte(#raw) == 13 then
            cr = "\r"
            line = raw:sub(1, -2)
        else
            cr = ""
            line = raw
        end
        -- An interior `\r`: a bare CR that is NOT the trailing CRLF terminator.
        local interior_cr = line:find("\r", 1, true) ~= nil
        -- Strict CRLF, scoped to framing. A bare LF or bare CR that terminates
        -- a boundary line, a header line, or the header/body separator (or a
        -- bare CR embedded in any of them) is a desync vector (a strict
        -- backend wants `\r\n--boundary`; a line-based parser accepts
        -- `\n--boundary`). Inside opaque part content a bare LF / CR is
        -- harmless data, so a legit text- or binary-file upload with Unix
        -- newlines or raw 0x0D bytes passes.
        if self.strict_crlf then
            local is_bnd = line:match(boundary_start) or line:match(boundary_end)
            local in_body = start_collecting_body
            -- framing = anything that isn't opaque (non-boundary) part content
            local is_framing = not (in_body and not is_bnd)
            if is_bnd and not first_line and prev_cr ~= "\r" then
                return nil, "bare LF before boundary delimiter (strict CRLF required on framing)"
            end
            if is_framing and cr ~= "\r" then
                return nil, "bare LF in multipart framing (strict CRLF required)"
            end
            if is_framing and interior_cr then
                return nil, "bare CR in multipart framing (strict CRLF required)"
            end
        end
        if line:match(boundary_end) then
            if self.debug then
                print("> END OF MULTIPART")
            end
            end_boundary_found = true
            start_collecting_headers = false
            start_collecting_body = false
            break
        end

        if line:match(boundary_start) then
            if self.debug then print("> START OF PART") end
            start_boundary_found = true
            part_count = part_count + 1
            t[part_count] = {raw_headers="",body="",body_buf={}}
            start_collecting_headers = true
            start_collecting_body = false
        end

        if start_collecting_headers then
            if self.debug then print("> HEADER LINE: " .. line) end
            t[part_count].raw_headers = t[part_count].raw_headers .. line .. "\r\n"
        end
        if start_collecting_body then
            if self.debug then print("> BODY LINE: " .. line) end
            -- Buffer body lines; join once after the loop. Per-line string
            -- concatenation here was O(n^2) on the line count (a large file
            -- upload, or a body padded with newlines, is thousands of lines).
            local body_buf = t[part_count].body_buf
            body_buf[#body_buf + 1] = line
        end


        if line == "" then
            if self.debug then print("> END OF HEADERS / START BODY") end
            if not start_boundary_found then
                if self.check_wrong_boundary then
                    return nil, "boundary sent with Content-Type not found in body"
                end
            end
            start_collecting_headers = false
            start_collecting_body = true
        end

        prev_cr = cr
        first_line = false
    end

    -- Gap #5: require the explicit closing `--<boundary>--` line. PHP
    -- (and some other backends) accept incomplete bodies; a strict WAF
    -- must reject so the WAF view matches what the backend will parse.
    if not end_boundary_found then
        if self.require_closing_boundary then
            return nil, "missing closing boundary '--" .. boundary .. "--'"
        end
    end

    for i, part in ipairs(t) do
        t[i].boundary = boundary

        -- A well-formed part body is delimited by CRLF--boundary, so at least
        -- one body line is always collected: even an empty field carries its
        -- delimiter CRLF. Zero collected lines means the boundary was glued
        -- straight onto the headers terminator with no body section (or the
        -- headers were never terminated) — a malformed part the backend and
        -- the WAF parse differently. Reject the whole body.
        if self.reject_bodyless_part and #t[i].body_buf == 0 then
            return nil, "malformed part (no body section; boundary glued to headers) in part " .. tostring(i)
        end

        -- Materialise the buffered body. Each collected line used to be stored
        -- with a trailing "\r\n" and the final one stripped by sub(1,-3);
        -- joining with "\r\n" reproduces exactly that normalised framing (no
        -- trailing separator) in O(n) instead of O(n^2).
        t[i].body = table.concat(t[i].body_buf, "\r\n")
        t[i].body_buf = nil
        t[i].content_length = #t[i].body

        -- remove last \r\n\r\n from raw_headers
        t[i].raw_headers = t[i].raw_headers:sub(1, -5)

        -- remove --<boundary>\r\n at the beginning of raw_headers
        t[i].raw_headers = t[i].raw_headers:gsub("^%-%-" .. boundary_escaped .. "\r\n", "")

        -- split raw_headers by \r\n
        t[i].headers = {}
        for header in t[i].raw_headers:gmatch("([^\r\n]+)") do
            local k, v = header:match("^([^:]+):%s*(.*)$")
            if k and v then
                -- validate header name
                local header_name_lowercase = k:lower()

                if not self:is_header_name_valid(header_name_lowercase) then
                    if self.validate_header_name then
                        return nil, "invalid header name: |" .. k:gsub("\r","\\r"):gsub("\n","\\n") .. "|"
                    end
                end

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
                if header_name_lowercase == "content-disposition" then
                    if not t[i].content_disposition then
                        t[i].content_disposition = v:gsub("[\r\n]+","")
                        local m_params = v:match("form%-data%;%s*(.+)")
                        -- Parse `; key=value; key="quoted value"; ...` params.
                        -- Use the quoted-aware tokenizer (Gap #3) so a `;`
                        -- inside a quoted value doesn't split the segment.
                        -- Each segment is then validated:
                        --   Gap #1: reject RFC 5987 `*=` ext-parameter syntax.
                        --   Gap #2: when require_quoted_params is on, only
                        --           accept RFC 2046 quoted-string form.
                        if m_params then
                            for _, segment in ipairs(tokenize_cd_params(m_params)) do
                                segment = segment:gsub("^%s+", ""):gsub("%s+$", "")
                                if segment ~= "" then
                                    -- Gap #1: RFC 5987 ext-parameter (`name*=`,
                                    -- `filename*=...`). Backends process and
                                    -- URL-decode the value while WAFs typically
                                    -- inspect the bare `filename=` only — the
                                    -- two views diverge.
                                    if segment:match("^[%w_]+%*%s*=") then
                                        if self.reject_filename_star then
                                            return nil, "RFC 5987 '*=' ext-parameter disallowed in request body content-disposition"
                                        end
                                    end
                                    local key, value
                                    key, value = segment:match('^([%w_%-]+)%s*=%s*"([^"]*)"$')
                                    if not key then
                                        if self.require_quoted_params then
                                            -- Gap #2: bareword/unquoted value
                                            -- (e.g. `filename=backdoor.php`).
                                            -- Reject explicitly if it parses
                                            -- as `key=...` — silently skipping
                                            -- would let the backend see a
                                            -- value the WAF didn't inspect.
                                            if segment:match("^[%w_%-]+%s*=") then
                                                return nil, "unquoted content-disposition parameter not allowed: " .. segment:sub(1, 80)
                                            end
                                        else
                                            key, value = segment:match('^([%w_%-]+)%s*=%s*(.*)$')
                                        end
                                    end
                                    if key and value then
                                        local key_lowercase = key:lower()
                                        if not t[i][key_lowercase] then
                                            if self.debug then print("> PARAM: " .. key_lowercase .. " = " .. value) end
                                            t[i][key_lowercase] = value
                                            if key_lowercase == "filename" then
                                                -- get the extension after the last "."
                                                t[i].extension = value:match("^.+%.(.+)$")
                                            end
                                        else
                                            if self.check_duplicated_content_disposition_param then
                                                return nil, "duplicated content-disposition parameter: " .. key_lowercase
                                            end
                                        end
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

                -- for loop on all parameters
                if self.validate_param_value then
                    for param_name,param_value in pairs(t[i]) do
                        if param_name ~= "body" then
                            local param_value_tostring = tostring(param_value)
                            -- check if param value contains %<hex><hex>
                            local percent_decode_count = 0
                            while re_match(param_value_tostring, "%[0-9a-fA-F][0-9a-fA-F]") do
                                if percent_decode_count >= 3 then
                                    break
                                end
                                param_value = ngx.unescape_uri(param_value)
                                param_value_tostring = tostring(param_value)
                                percent_decode_count = percent_decode_count + 1
                            end
                            -- check if null byte in param_value
                            if re_match(tostring(param_value), "\\0") then
                                return nil, "null byte found in parameter value: " .. param_name
                            end
                        end
                    end
                end
            end
        end

        -- raw_headers is internal-only (used by the parser for validation);
        -- nullify to keep the returned table small. `headers` is kept so
        -- downstream variable resolution can expose each part header as a
        -- native variable (request.body.multipart.part.header.*).
        t[i].raw_headers = nil

        -- if filename but not content-type, set content-type to application/octet-stream
        if t[i].filename and not t[i].content_type then
            t[i].content_type = "application/octet-stream"
        end

        if not t[i].content_disposition then
            -- t[i] = nil
            if self.check_content_disposition then
                return nil, "no content-disposition found in part"
            end
        end

        if not t[i].name then
            if self.check_name_in_content_disposition then
                return nil, "no name parameter found in content-disposition header part"
            end
        end
    end

    return t, nil
end

function _M.table_to_multipart(self, t)
    -- generate boundary string: "KarnaBoundary" + timestamp + random
    local boundary = "KarnaBoundary"..tostring(ngx.now()):gsub("%.","")..tostring({}):sub(10)
    local multipart_message = ""

    for _,part in ipairs(t) do
        multipart_message = multipart_message .. "--"..boundary.."\r\n"
        if part.content_disposition then
            if part.name then
                -- escape double quotes in part.name
                part.name = part.name:gsub('"', '\\"')
                local filename_param = ""
                if part.filename then
                    -- escape double quotes in filename
                    part.filename = part.filename:gsub('"', '\\"')
                    filename_param = "; filename=\""..part.filename.."\""
                end
                multipart_message = multipart_message .. "Content-Disposition: form-data; name=\""..part.name.."\""..filename_param.."\r\n"
            end
        end
        if part.content_type then
            multipart_message = multipart_message .. "Content-Type: "..part.content_type.."\r\n"
        end
        multipart_message = multipart_message .. "\r\n" .. part.body .. "\r\n"
    end

    multipart_message = multipart_message .. "--"..boundary.."--"
    return multipart_message, nil
end

return _M
