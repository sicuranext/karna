-- ka-unittest/multipart_security_gaps.lua
--
-- Coverage for the 5 security hardening fixes in ka_multipart.lua against
-- the bypass classes documented at
-- https://blog.sicuranext.com/breaking-down-multipart-parsers-validation-bypass/
-- Each test references the gap number from the audit memory
-- ([[project-security-multipart-parser]]).
--
-- Run from repo root:   luajit ka-unittest/multipart_security_gaps.lua
--
-- We bypass the Kong require chain: load only ka_multipart and stub
-- the OpenResty bits it uses.

package.path = "./kong/plugins/karna/modules/?.lua;" .. package.path

-- Stub ngx (the multipart parser uses ngx.re.match for boundary extraction
-- and ngx.unescape_uri for the percent-decode counter loop).
_G.ngx = {
    re = {
        match = function(s, pattern, _flags)
            if pattern == [[;\s*boundary\s*=\s*([0-9a-zA-Z'()+_,./:=?-]+)]] then
                local b = s:match(";%s*boundary%s*=%s*([0-9a-zA-Z'()+_,./:=?%-]+)")
                if b then return { b } end
                return nil
            end
            if pattern == "%[0-9a-fA-F][0-9a-fA-F]" then
                return s:match("%%[0-9a-fA-F][0-9a-fA-F]") and { true } or nil
            end
            if pattern == "\\0" then
                return s:find("\0", 1, true) and { true } or nil
            end
            return nil
        end,
        find = function(s, pattern, _flags)
            -- mirror ngx.re.find for the two PCRE patterns ka_multipart's
            -- strict_crlf scan uses: bare LF ([^\r]\n) and bare CR (\r[^\n]).
            -- Returns the match start (truthy) or nil, like the real find.
            if pattern == "[^\\r]\\n" then return s:find("[^\r]\n") end
            if pattern == "\\r[^\\n]" then return s:find("\r[^\n]") end
            return nil
        end
    },
    unescape_uri = function(str)
        if not str then return nil end
        return (str:gsub("%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end))
    end
}

-- inspect is required by the module but only used in debug prints — stub it.
package.preload["inspect"] = function() return function(...) return "" end end

local ok, mp = pcall(require, "ka_multipart")
if not ok then
    io.stderr:write("FAIL: cannot load ka_multipart.lua: " .. tostring(mp) .. "\n")
    os.exit(1)
end

local failures = 0
local function check(label, cond, hint)
    if cond then
        print("  PASS  " .. label)
    else
        print("  FAIL  " .. label .. (hint and ("  (" .. hint .. ")") or ""))
        failures = failures + 1
    end
end

-- Helper: build a multipart body string. `parts` is a list of part specs.
-- Each part: { cd_header = "Content-Disposition: ...", content_type = "...", body = "..." }
-- opts: { boundary, bare_lf, skip_closing }
local function build_body(parts, opts)
    opts = opts or {}
    local CRLF = opts.bare_lf and "\n" or "\r\n"
    local boundary = opts.boundary or "X"
    local out = {}
    for _, p in ipairs(parts) do
        out[#out + 1] = "--" .. boundary
        out[#out + 1] = p.cd_header or ('Content-Disposition: form-data; name="' .. (p.name or "f") .. '"')
        if p.content_type then
            out[#out + 1] = "Content-Type: " .. p.content_type
        end
        out[#out + 1] = ""
        out[#out + 1] = p.body or "value"
    end
    if not opts.skip_closing then
        out[#out + 1] = "--" .. boundary .. "--"
    end
    return table.concat(out, CRLF)
end

local CT = "multipart/form-data; boundary=X"

-- ===========================================================================
print("== Gap #1: filename*= rejection (Bypass #5 / #5a) ==")
-- ===========================================================================

do
    local body = build_body({
        { cd_header = 'Content-Disposition: form-data; name="f"; filename*=UTF-8\'\'evil%2Ephp', body = "x" }
    })
    local r, err = mp:parse(body, CT)
    check("filename*= alone → rejected",
          r == nil and err and err:find("ext%-parameter disallowed"),
          "got: " .. tostring(err))
end

do
    -- Bypass #5a: filename="safe.png"; filename*=...evil
    local body = build_body({
        { cd_header = 'Content-Disposition: form-data; name="f"; filename="safe.png"; filename*=UTF-8\'\'evil.js', body = "x" }
    })
    local r, err = mp:parse(body, CT)
    check("filename + filename*= combo → rejected",
          r == nil and err and err:find("ext%-parameter disallowed"),
          "got: " .. tostring(err))
end

do
    mp.reject_filename_star = false
    local body = build_body({
        { cd_header = 'Content-Disposition: form-data; name="f"; filename*=UTF-8\'\'x', body = "x" }
    })
    local r, _err = mp:parse(body, CT)
    mp.reject_filename_star = true
    check("reject_filename_star=false → parses (still no leak as filename)",
          r ~= nil and r[1] ~= nil)
end

-- ===========================================================================
print("== Gap #2: require quoted CD params (Bypass #3 / #8) ==")
-- ===========================================================================

do
    local body = build_body({
        { cd_header = 'Content-Disposition: form-data; name="f"; filename=backdoor.php', body = "x" }
    })
    local r, err = mp:parse(body, CT)
    check("unquoted filename → rejected",
          r == nil and err and err:find("unquoted content%-disposition"),
          "got: " .. tostring(err))
end

do
    local body = build_body({
        { cd_header = 'Content-Disposition: form-data; name=evil', body = "x" }
    })
    local r, err = mp:parse(body, CT)
    check("unquoted name → rejected",
          r == nil and err and err:find("unquoted content%-disposition"),
          "got: " .. tostring(err))
end

do
    local body = build_body({
        { cd_header = 'Content-Disposition: form-data; name="ok"; filename="ok.txt"', body = "x" }
    })
    local r, err = mp:parse(body, CT)
    check("quoted params still accepted",
          r and r[1] and r[1].name == "ok" and r[1].filename == "ok.txt",
          "err: " .. tostring(err))
end

do
    mp.require_quoted_params = false
    local body = build_body({
        { cd_header = 'Content-Disposition: form-data; name=plain', body = "x" }
    })
    local r, err = mp:parse(body, CT)
    mp.require_quoted_params = true
    check("require_quoted_params=false → unquoted accepted",
          r and r[1] and r[1].name == "plain",
          "err: " .. tostring(err))
end

-- ===========================================================================
print("== Gap #3: quoted-aware ; tokenizer ==")
-- ===========================================================================

do
    local body = build_body({
        { cd_header = 'Content-Disposition: form-data; name="evil;.txt"', body = "x" }
    })
    local r, err = mp:parse(body, CT)
    check("name='evil;.txt' preserves the embedded ;",
          r and r[1] and r[1].name == "evil;.txt",
          "got name=" .. tostring(r and r[1] and r[1].name) .. " err=" .. tostring(err))
end

do
    local body = build_body({
        { cd_header = 'Content-Disposition: form-data; name="f"; filename="weird;name.txt"', body = "x" }
    })
    local r, err = mp:parse(body, CT)
    check("filename='weird;name.txt' preserves the embedded ;",
          r and r[1] and r[1].filename == "weird;name.txt",
          "got filename=" .. tostring(r and r[1] and r[1].filename) .. " err=" .. tostring(err))
end

do
    -- Tokenizer must still split legit ;-separated params.
    local body = build_body({
        { cd_header = 'Content-Disposition: form-data; name="a"; filename="b.txt"', body = "x" }
    })
    local r, err = mp:parse(body, CT)
    check("multi-param CD still splits correctly",
          r and r[1] and r[1].name == "a" and r[1].filename == "b.txt",
          "err: " .. tostring(err))
end

-- ===========================================================================
print("== Gap #4: strict CRLF (Bypass #2) ==")
-- ===========================================================================

do
    local body = build_body({ { name = "a" } }, { bare_lf = true })
    local r, err = mp:parse(body, CT)
    check("bare LF in body → rejected",
          r == nil and err and err:find("bare LF"),
          "got: " .. tostring(err))
end

do
    local body = build_body({ { name = "a" } })
    local r, err = mp:parse(body, CT)
    check("proper CRLF body → accepted",
          r and r[1],
          "err: " .. tostring(err))
end

do
    mp.strict_crlf = false
    local body = build_body({ { name = "a" } }, { bare_lf = true })
    local _r, err = mp:parse(body, CT)
    mp.strict_crlf = true
    check("strict_crlf=false → no 'bare LF' error",
          not (err and err:find("bare LF")),
          "got: " .. tostring(err))
end

-- ===========================================================================
print("== Gap #4b: bare CR scoped to framing (binary-upload false positive) ==")
-- ===========================================================================
-- A bare CR (0x0D not followed by 0x0A) is ordinary data inside a part body:
-- binary uploads (images/PDFs) carry thousands of them. The old body-wide
-- bare-CR scan rejected every such upload ("bare CR found in body"). It's now
-- enforced only on FRAMING; inside part content a bare CR is kept verbatim.

do
    -- The Ghost image-upload FP: a file part whose bytes contain a bare CR.
    local body = build_body({
        { cd_header = 'Content-Disposition: form-data; name="file"; filename="pic.png"',
          content_type = "image/png",
          body = "PNG\r\137DATA\rMORE" },  -- raw 0x0D bytes, not CRLF
    })
    local r, err = mp:parse(body, CT)
    check("binary file with bare CR → accepted (no 'bare CR' block)",
          r and r[1] and not (err and err:find("bare CR")),
          "got: " .. tostring(err))
    check("binary file body preserved byte-for-byte (CR kept, none dropped)",
          r and r[1] and r[1].body == "PNG\r\137DATA\rMORE",
          "got body=" .. tostring(r and r[1] and r[1].body))
end

do
    -- Non-file field value with a bare CR must survive into the parsed value
    -- (byte-drop here would let an attacker hide a payload from ARGS scanning).
    local body = build_body({
        { cd_header = 'Content-Disposition: form-data; name="q"', body = "foo\rbar<script>" },
    })
    local r, err = mp:parse(body, CT)
    check("non-file value with bare CR → preserved (no evasion via dropped bytes)",
          r and r[1] and r[1].body == "foo\rbar<script>",
          "got body=" .. tostring(r and r[1] and r[1].body) .. " err=" .. tostring(err))
end

do
    -- Bare CR embedded in a part HEADER line is framing → still rejected.
    local body = '--X\r\nContent-Disposition: form-data; name="a"\rEVIL\r\n\r\nv\r\n--X--\r\n'
    local r, err = mp:parse(body, CT)
    check("bare CR in a header line → rejected",
          r == nil and err and err:find("bare CR in multipart framing"),
          "got: " .. tostring(err))
end

do
    -- Bare CR embedded in the opening boundary line is framing → still rejected.
    local body = '--X\rGARBAGE\r\nContent-Disposition: form-data; name="a"\r\n\r\nv\r\n--X--\r\n'
    local r, err = mp:parse(body, CT)
    check("bare CR in the boundary line → rejected",
          r == nil and err and err:find("bare CR in multipart framing"),
          "got: " .. tostring(err))
end

do
    -- A bare CR right before the closing delimiter (framing desync attempt):
    -- the delimiter never surfaces as a clean line, so the closing-boundary
    -- gate rejects it. Either way the request is denied, never parsed 200.
    local body = '--X\r\nContent-Disposition: form-data; name="a"\r\n\r\nvalue\r--X--\r\n'
    local r, err = mp:parse(body, CT)
    check("bare CR glued before closing delimiter → rejected",
          r == nil and err ~= nil,
          "got: " .. tostring(err))
end

-- ===========================================================================
print("== Gap #5: require closing boundary (Bypass #4) ==")
-- ===========================================================================

do
    local body = build_body({ { name = "a" } }, { skip_closing = true })
    local r, err = mp:parse(body, CT)
    check("missing --boundary-- → rejected",
          r == nil and err and err:find("missing closing boundary"),
          "got: " .. tostring(err))
end

do
    local body = build_body({ { name = "a" } })
    local r, err = mp:parse(body, CT)
    check("closing --boundary-- present → accepted",
          r and r[1],
          "err: " .. tostring(err))
end

do
    mp.require_closing_boundary = false
    local body = build_body({ { name = "a" } }, { skip_closing = true })
    local _r, err = mp:parse(body, CT)
    mp.require_closing_boundary = true
    check("require_closing_boundary=false → no 'missing closing' error",
          not (err and err:find("missing closing boundary")),
          "got: " .. tostring(err))
end

-- ===========================================================================
print("== Regression: legitimate quoted single-part body still parses ==")
-- ===========================================================================

do
    local body = build_body({
        { cd_header = 'Content-Disposition: form-data; name="username"',          body = "andrea" },
        { cd_header = 'Content-Disposition: form-data; name="avatar"; filename="me.png"',
          content_type = "image/png",
          body = "PNGDATA" },
    })
    local r, err = mp:parse(body, CT)
    check("two-part legit form → both parts parsed",
          r and #r == 2
            and r[1].name == "username" and r[1].body == "andrea"
            and r[2].name == "avatar"   and r[2].filename == "me.png"
            and r[2].content_type and r[2].content_type:find("image/png"),
          "err: " .. tostring(err) .. " r=" .. tostring(r))
end

print(string.format("\n%d failure(s)", failures))
os.exit(failures == 0 and 0 or 1)
