-- ka-unittest/auditlog_utf8_sanitize.lua
--
-- Guards ka_utils.sanitize_utf8 — the last thing that touches an audit record
-- before it hits disk. Its job: no line leaves Karna unless it is valid UTF-8.
--
-- Why this is a security guard and not log cosmetics. cjson does NOT validate
-- UTF-8; it copies bytes >= 0x80 through untouched and reports no error. The
-- bytes in an audit record are attacker-controlled (matched values, request
-- headers, the URI), so before this guard existed a client could hand Karna a
-- byte that made its own record undecodable, and every UTF-8-strict consumer
-- (Filebeat / Fluent Bit / Vector / Elasticsearch / json.loads) dropped the
-- line. Two confirmed shapes, both with no rule authoring involved:
--   * ?p=<script>alert(1)</script>%c3%28  -> blocked 403, record unreadable
--   * X-Evil: abc\xc3(def                 -> benign request, no rule match,
--                                           record unreadable anyway
-- That is an on-demand audit-trail suppression primitive, so the invariant is
-- pinned here rather than left to review.
--
-- Second shape covered: Karna cutting a character in half itself. matched_value
-- is clipped with a byte-based string.sub(v, 1, 100) in ~30 places in
-- ka_engine, so a multibyte codepoint straddling byte 100 leaves an orphan lead
-- byte. Escaping rather than dropping keeps the record honest — the reader sees
-- which byte arrived.
--
-- The test asserts the output property with an INDEPENDENT UTF-8 validator
-- written below, not by reusing the implementation, so a bug in the validation
-- logic cannot pass itself.
--
-- Run from repo root:
--   lua    ka-unittest/auditlog_utf8_sanitize.lua
--   luajit ka-unittest/auditlog_utf8_sanitize.lua

package.path = "./kong/plugins/karna/modules/?.lua;" .. package.path

-- ngx / kong stubs: ka_utils captures kong.request.* etc. at module load.
package.preload["kong.plugins.karna.version"] = function()
    return { version = "test", commit = "test", built_at = "test" }
end
_G.ngx = {
    re = { match = function() return nil end },
    var = setmetatable({}, { __index = function() return nil end }),
    log = function() end,
}
_G.kong = {
    log = { err = function() end, warn = function() end, debug = function() end },
    request = {
        get_header = function() return nil end, get_headers = function() return {} end,
        get_path_with_query = function() return "/" end, get_method = function() return "GET" end,
        get_http_version = function() return 1.1 end,
    },
    service = { response = { get_headers = function() return {} end, get_status = function() return 200 end } },
    response = { get_status = function() return 200 end },
}

local utils = dofile("./kong/plugins/karna/modules/ka_utils.lua")
local sanitize = utils.sanitize_utf8

local failures = 0
local function check(name, cond, detail)
    if cond then print("  ok   - " .. name)
    else failures = failures + 1; print("  FAIL - " .. name .. (detail and ("  (" .. detail .. ")") or "")) end
end

-- Independent validator. Deliberately written from the UTF-8 table rather than
-- copied from the implementation: it is the oracle, not a mirror.
local function is_valid_utf8(s)
    local i, len = 1, #s
    while i <= len do
        local c = s:byte(i)
        local n
        if     c <= 0x7F then n = 1
        elseif c >= 0xC2 and c <= 0xDF then n = 2
        elseif c >= 0xE0 and c <= 0xEF then n = 3
        elseif c >= 0xF0 and c <= 0xF4 then n = 4
        else return false, i end
        if i + n - 1 > len then return false, i end
        for k = 1, n - 1 do
            local cc = s:byte(i + k)
            if cc < 0x80 or cc > 0xBF then return false, i end
        end
        if n > 1 then
            local c1 = s:byte(i + 1)
            if (c == 0xE0 and c1 < 0xA0)      -- overlong 3-byte
            or (c == 0xED and c1 > 0x9F)      -- UTF-16 surrogate half
            or (c == 0xF0 and c1 < 0x90)      -- overlong 4-byte
            or (c == 0xF4 and c1 > 0x8F) then -- beyond U+10FFFF
                return false, i
            end
        end
        i = i + n
    end
    return true
end

local function hex(s)
    return (s:gsub(".", function(c) return string.format("%02x ", c:byte()) end))
end

-- ---------------------------------------------------------------------------
print("valid input passes through untouched:")
-- ---------------------------------------------------------------------------

-- The fast path matters: pure-ASCII records are the vast majority of traffic
-- and must not be rebuilt.
local ascii = '{"value":"<script>alert(1)</script>","on":"request.arg.value:p"}'
check("pure ASCII returns the identical string", sanitize(ascii) == ascii)
check("empty string survives", sanitize("") == "")

local valid_cases = {
    ["2-byte (e-acute)"]        = "caf\xc3\xa9",
    ["3-byte (almost-equal)"]   = "circa \xe2\x89\x88 13%",
    ["4-byte (party popper)"]   = "done \xf0\x9f\x8e\x89",
    ["Cyrillic"]                = "\xd0\xbf\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82",
    ["CJK"]                     = "\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e",
    ["U+10FFFF (top of range)"] = "\xf4\x8f\xbf\xbf",
    ["U+0080 (low 2-byte)"]     = "\xc2\x80",
}
for name, s in pairs(valid_cases) do
    check("valid UTF-8 is not rewritten: " .. name, sanitize(s) == s, hex(sanitize(s)))
end

-- ---------------------------------------------------------------------------
print("")
print("bytes Karna produces itself (truncation at byte 100):")
-- ---------------------------------------------------------------------------

-- Exactly what string.sub(v, 1, 100) does when a codepoint straddles the cut.
check("orphan 2-byte lead becomes text",
      sanitize("A\xc3") == "A\\\\xc3", hex(sanitize("A\xc3")))
check("orphan 3-byte lead + 1 continuation becomes text",
      sanitize("A\xe2\x89") == "A\\\\xe2\\\\x89", hex(sanitize("A\xe2\x89")))
check("orphan 4-byte lead becomes text",
      sanitize("A\xf0\x9f\x8e") == "A\\\\xf0\\\\x9f\\\\x8e", hex(sanitize("A\xf0\x9f\x8e")))

for cut = 1, 4 do
    -- Take a valid multibyte string and clip it at every offset: whatever
    -- comes out must be valid UTF-8.
    local s = ("A"):rep(3) .. "\xf0\x9f\x8e\x89" .. "tail"
    local clipped = s:sub(1, 3 + cut)
    local out = sanitize(clipped)
    check("clip inside a 4-byte codepoint at +" .. cut .. " yields valid UTF-8",
          is_valid_utf8(out), hex(out))
end

-- ---------------------------------------------------------------------------
print("")
print("bytes the client supplies (no truncation involved):")
-- ---------------------------------------------------------------------------

local hostile = {
    ["stray continuation 0x80"]      = "abc\x80def",
    ["stray continuation 0xbf"]      = "abc\xbfdef",
    ["overlong 2-byte lead 0xc0"]    = "abc\xc0\xafdef",
    ["overlong 2-byte lead 0xc1"]    = "abc\xc1\xbfdef",
    ["overlong 3-byte (/)"]          = "abc\xe0\x80\xafdef",
    ["overlong 4-byte"]              = "abc\xf0\x80\x80\xafdef",
    ["UTF-16 surrogate half"]        = "abc\xed\xa0\x80def",
    ["beyond U+10FFFF (0xf4 0x90)"]  = "abc\xf4\x90\x80\x80def",
    ["invalid lead 0xf5"]            = "abc\xf5\x80\x80\x80def",
    ["invalid lead 0xff"]            = "abc\xffdef",
    ["truncated sequence mid-string"]= "abc\xe2(def",
    ["the %c3%28 evasion payload"]   = "<script>alert(1)</script>\xc3(",
    ["the X-Evil header payload"]    = "abc\xc3(def",
    ["all 256 byte values"]          = (function()
        local t = {}
        for b = 0, 255 do t[#t + 1] = string.char(b) end
        return table.concat(t)
    end)(),
}
for name, s in pairs(hostile) do
    local out = sanitize(s)
    local valid, at = is_valid_utf8(out)
    check("hostile input yields valid UTF-8: " .. name, valid,
          valid and nil or ("first bad byte at " .. tostring(at) .. " -> " .. hex(out)))
end

check("a bad byte in the middle keeps the surrounding text",
      sanitize("abc\xffdef") == "abc\\\\xffdef", hex(sanitize("abc\xffdef")))
check("every byte of an illegal sequence is escaped, none silently dropped",
      sanitize("\xe0\x80\xaf") == "\\\\xe0\\\\x80\\\\xaf", hex(sanitize("\xe0\x80\xaf")))
check("valid and invalid interleaved keep their order",
      sanitize("\xc3\xa9\xff\xc3\xa8") == "\xc3\xa9\\\\xff\xc3\xa8",
      hex(sanitize("\xc3\xa9\xff\xc3\xa8")))

-- ---------------------------------------------------------------------------
print("")
print("JSON safety of the substitution:")
-- ---------------------------------------------------------------------------

-- The replacement is inserted into an ALREADY-ENCODED JSON line, so it must be
-- ASCII, must not introduce a raw newline, and must carry two backslashes on
-- the wire so that a decoder yields the 4-character text \xc3 (one backslash).
-- An odd number of backslashes would turn an encoding bug into a JSON syntax
-- error, which is strictly worse: the whole line would fail to parse.
local out = sanitize('{"value":"AAA\xc3","on":"request.header.value:x-evil"}')
check("sanitized line is valid UTF-8", is_valid_utf8(out), hex(out))
check("substitution is pure ASCII", not out:find("[\128-\255]"))
check("substitution introduces no raw newline", not out:find("[\r\n]"))
check("substitution carries an even number of backslashes",
      select(2, out:gsub("\\", "")) % 2 == 0)
check("JSON structure characters are untouched",
      out == '{"value":"AAA\\\\xc3","on":"request.header.value:x-evil"}', out)

-- The escape text must not itself be re-escapable into something else: NN is
-- always two lowercase hex digits, so \xc3 can never read as \xc (a broken
-- \uXXXX-style truncation of our own making).
for _, b in ipairs({ 0x80, 0xc0, 0xf5, 0xff }) do
    local o = sanitize(string.char(b))
    check(string.format("byte 0x%02x escapes to exactly 5 ASCII chars", b),
          #o == 5 and o == string.format("\\\\x%02x", b), hex(o))
end

print("")
if failures == 0 then print("ALL PASS"); os.exit(0)
else print(tostring(failures) .. " FAILURE(S)"); os.exit(1) end
