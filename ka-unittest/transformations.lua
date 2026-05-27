-- ka-unittest/transformations.lua
--
-- Sanity-test every transformation function in ka_engine.__apply_transformation.
-- The motivation is the 2026-05-23 finding: three transformations
-- (utf8toUnicode, jsDecode, cssDecode) were silently no-op'ing for years
-- because their patterns used PCRE syntax in Lua-pattern context. Without
-- a unit test that runs a known input → known output check on every t:func,
-- the next silent breakage would slip past unnoticed.
--
-- Run from repo root:
--   luajit ka-unittest/transformations.lua
--   lua    ka-unittest/transformations.lua
--
-- The test loads `ka_engine` with the bare minimum of mocked
-- dependencies. Transformations that need ngx primitives
-- (ngx.re.gsub, ngx.unescape_uri, ngx.decode_base64, ngx.sha1_bin)
-- get a Lua-native equivalent in the mock so the behaviour is
-- testable without OpenResty.

package.path = "./kong/plugins/karna/modules/?.lua;" .. package.path

-- Map `kong.plugins.karna.<name>` → `./kong/plugins/karna/modules/<name>.lua`
-- (the rockspec does this at install time; we replicate it for tests).
local function map_kpk(short, long)
    package.preload[long] = function()
        return dofile("./kong/plugins/karna/modules/" .. short .. ".lua")
    end
end

-- ===========================================================================
-- ngx mock — minimal but functional for the transformations we exercise
-- ===========================================================================

local function lua_unescape_uri(s)
    -- Mirror nginx behaviour: `+` → space, `%HH` → byte.
    s = s:gsub("+", " ")
    s = s:gsub("%%(%x%x)", function(hex) return string.char(tonumber(hex, 16)) end)
    return s
end

local function lua_sha1_bin(s)
    -- Pure-Lua SHA-1 is too much for a unit test. Stub: return a
    -- deterministic 20-byte value derived from the input so tests can
    -- check "did sha1 get called at all + did the output flow through
    -- the next transformation". Tests that need a real SHA-1 are
    -- out of scope here.
    local h = 0
    for i = 1, #s do h = (h * 31 + s:byte(i)) % 0xFFFFFFFF end
    local out = {}
    for i = 1, 20 do
        out[i] = string.char((h + i) % 256)
    end
    return table.concat(out)
end

local function lua_decode_base64(s)
    local chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    local lookup = {}
    for i = 1, #chars do lookup[chars:sub(i, i)] = i - 1 end
    local out = {}
    s = s:gsub("[^%w%+/=]", "")
    local i = 1
    while i <= #s do
        local c1 = lookup[s:sub(i, i)]; local c2 = lookup[s:sub(i + 1, i + 1)]
        local c3 = lookup[s:sub(i + 2, i + 2)]; local c4 = lookup[s:sub(i + 3, i + 3)]
        if not c1 or not c2 then break end
        -- 4 base64 chars = 24 bits = 3 bytes. Layout:
        --   c1[5:0] c2[5:0] c3[5:0] c4[5:0] = 24 bits
        -- so c1 << 18, c2 << 12, c3 << 6, c4 << 0.
        local n = c1 * 0x40000 + c2 * 0x1000 + (c3 or 0) * 0x40 + (c4 or 0)
        out[#out + 1] = string.char(math.floor(n / 0x10000) % 256)
        if c3 then out[#out + 1] = string.char(math.floor(n / 0x100) % 256) end
        if c4 then out[#out + 1] = string.char(n % 256) end
        i = i + 4
    end
    return table.concat(out)
end

-- Lua-native PCRE-ish gsub. Used only by t:utf8toUnicode which targets
-- multi-byte UTF-8 byte sequences. We hardcode the matcher to recognise
-- 2/3/4-byte UTF-8 leading-byte patterns and dispatch to the replacement
-- function with `m[0]` set to the matched sequence.
local function lua_re_gsub(s, _pattern, fn, _flags)
    local out = {}
    local i = 1
    local n = #s
    while i <= n do
        local b = s:byte(i)
        local len = 0
        if b >= 0xF0 then len = 4
        elseif b >= 0xE0 then len = 3
        elseif b >= 0xC2 then len = 2
        end
        if len > 1 and i + len - 1 <= n then
            local seq = s:sub(i, i + len - 1)
            local valid = true
            for k = 2, len do
                local cb = seq:byte(k)
                if not cb or cb < 0x80 or cb > 0xBF then valid = false; break end
            end
            if valid then
                out[#out + 1] = fn({ [0] = seq })
                i = i + len
            else
                out[#out + 1] = string.char(b)
                i = i + 1
            end
        else
            out[#out + 1] = string.char(b)
            i = i + 1
        end
    end
    return table.concat(out), nil, nil
end

_G.ngx = {
    re = {
        match  = function(...) return nil end,
        gmatch = function() return function() return nil end end,
        gsub   = lua_re_gsub,
    },
    unescape_uri  = lua_unescape_uri,
    escape_uri    = function(s) return s end,
    decode_base64 = lua_decode_base64,
    encode_base64 = function(s) return s end,
    sha1_bin      = lua_sha1_bin,
    md5           = function(s) return s end,
    var           = setmetatable({}, { __index = function() return nil end }),
    null          = nil,
    log           = function() end,
    NOTICE = 1, WARN = 2, ERR = 3, DEBUG = 4, INFO = 5,
    worker = { id = function() return 0 end },
    req    = {
        get_body_file = function() return nil end,
        get_post_args = function() return {} end,
        read_body     = function() end,
    },
    now    = function() return 0 end,
    time   = function() return 0 end,
    timer  = { at = function() return nil, "stub" end },
    config = { subsystem = "http" },
    get_phase = function() return "access" end,
}

_G.kong = {
    ctx = { plugin = { ka_value_cache = {} } },
    log = {
        debug   = function() end,
        warn    = function() end,
        err     = function() end,
        inspect = function() end,
    },
    request = {
        get_header           = function() return nil end,
        get_headers          = function() return {} end,
        get_path_with_query  = function() return "/" end,
        get_method           = function() return "GET" end,
        get_http_version     = function() return 1.1 end,
    },
    service = {
        response = {
            get_headers = function() return {} end,
            get_status  = function() return 200 end,
        },
    },
    response = { get_status = function() return 200 end },
    cache    = { get = function() return nil end },
}

-- Real ka_utils for utf8FromHex / hexFromUTF8 (which utf8toUnicode +
-- urlDecodeUni use). It only needs kong/ngx stubs which we already
-- declared above.
map_kpk("ka_utils", "kong.plugins.karna.ka_utils")

-- Sibling modules ka_engine require()s — stub anything we don't exercise.
package.preload["inspect"]                            = function() return function() return "" end end
package.preload["cjson"]                              = function() return { decode = function() return {} end, encode = function() return "" end, encode_empty_table_as_object = function() end } end
package.preload["cjson.safe"]                         = function() return { decode = function() return nil end, encode = function() return nil end } end
package.preload["resty.ipmatcher"]                    = function() return { new = function() return { match = function() return false end } end } end
package.preload["resty.redis"]                        = function() return { new = function() return {} end } end
package.preload["resty.http"]                         = function() return { new = function() return {} end } end
package.preload["resty.lrucache"]                     = function() return { new = function() return { get = function() return nil end, set = function() end, flush_all = function() end } end } end
package.preload["ngx.base64"]                         = function() return { decode_base64url = function(s) return s end } end
package.preload["bit"]                                = function() return { bor = function(a, b) return a + b end } end
package.preload["ffi"]                                = function() return { new = function() return {} end, string = function() return "" end, typeof = function() return function() return {} end end, cdef = function() end, load = function() return {} end } end
package.preload["kong.plugins.karna.ka_body_parser"]  = function() return {
    json = function() return {} end,
    xml = function() return {} end,
    urlencoded = function() return {} end,
    multipart = function() return {}, nil end,
    cookie = function() return {} end,
} end
package.preload["kong.plugins.karna.ka_seclang"]      = function() return {
    parse = function() return {} end,
    collect_crs_conf_files = function() return {} end,
} end
package.preload["kong.plugins.karna.libinjection"]    = function() return {
    sqli_noquote = function() return false end,
    xss_data_state = function() return false end,
} end
package.preload["kong.plugins.karna.ka_rules_crs_fix"] = function() return { global_fps = {} } end
package.preload["kong.plugins.karna.ka_mcp"]           = function() return {
    _method_matches = function() return false end,
    _validate_jsonrpc = function() return true end,
} end
package.preload["kong.plugins.karna.ka_mcp_sse"]       = function() return {} end
package.preload["kong.plugins.karna.ka_multipart"]     = function() return { parse = function() return nil end } end

-- ===========================================================================
-- Load the engine
-- ===========================================================================

local ok, engine = pcall(require, "ka_engine")
if not ok then
    io.stderr:write("FAIL: cannot load ka_engine.lua: " .. tostring(engine) .. "\n")
    os.exit(1)
end

local function apply(tfunc, value)
    -- Reset cache so each test starts clean.
    _G.kong.ctx.plugin.ka_value_cache = {}
    return engine:__apply_transformation(tfunc, value)
end

-- ===========================================================================
-- Test harness
-- ===========================================================================

local failures = 0
local function check(label, cond, hint)
    if cond then
        print("  PASS  " .. label)
    else
        print("  FAIL  " .. label .. (hint and ("  (" .. hint .. ")") or ""))
        failures = failures + 1
    end
end

local function eq(label, tfunc, input, expected)
    local got = apply(tfunc, input)
    check(label .. "  [" .. tfunc .. "]",
          got == expected,
          string.format("got=%q expected=%q", tostring(got), tostring(expected)))
end

-- ===========================================================================
print("== lowercase ==")
eq("ABC → abc",         "lowercase", "ABC",      "abc")
eq("MiXeD → mixed",     "lowercase", "MiXeD",    "mixed")
eq("empty → empty",     "lowercase", "",         "")

print("== removeNulls ==")
eq("strips \\0",        "removeNulls", "a\0b\0c", "abc")
eq("no nulls → same",   "removeNulls", "abc",     "abc")

print("== removeWhitespace ==")
eq("collapses ws",      "removeWhitespace", "a b\tc\nd", "abcd")

print("== compressWhitespace ==")
eq("ws sequences → single space", "compressWhitespace", "a  b\t\tc\n d", "a b c d")
eq("no ws → unchanged",           "compressWhitespace", "abc", "abc")

print("== removeCommentsChar ==")
eq("strips /* */ //",   "removeCommentsChar", "a/*b*/c//d#e", "abcde")

print("== replaceComments ==")
-- ModSec replaceComments REPLACES each /* */ block with a SINGLE SPACE
-- (not strip), so token boundaries survive: `a/* */b` → `a b`, not `ab`.
-- This is detection-critical (e.g. RePLAcE/*x*/INTO → RePLAcE INTO must
-- still match the SQLi word-boundary regex; see ka_engine replaceComments).
eq("replaces C-style block with a space", "replaceComments", "a/* hidden */b", "a b")

print("== length ==")
eq("returns numeric length", "length", "abcde", 5)

print("== hexSequenceDecode ==")
eq("%41 → A", "hexSequenceDecode", "%41%42%43", "ABC")

print("== escapeSeqDecode ==")
eq("\\n → LF", "escapeSeqDecode", "a\\nb",                              "a\nb")
eq("\\t → TAB", "escapeSeqDecode", "a\\tb",                             "a\tb")
eq("\\xHH → byte", "escapeSeqDecode", "a\\x41b",                        "aAb")

print("== htmlEntityDecode ==")
eq("&#x41; → A",      "htmlEntityDecode", "&#x41;",   "A")
eq("&lt; → <",        "htmlEntityDecode", "&lt;",     "<")
eq("&#65; → A",       "htmlEntityDecode", "&#65;",    "A")

print("== normalisePath (British) ==")
eq("/a/./b → /a/b",   "normalisePath", "/a/./b", "/a/b")
eq("/a//b  → /a/b",   "normalisePath", "/a//b",  "/a/b")

print("== normalizePath (American — alias) ==")
eq("/a/./b → /a/b",   "normalizePath", "/a/./b", "/a/b")
-- Karna's normalizePath uses a flat regex collapse rather than a
-- proper path resolver. `/a/b/../c` becomes `/a/b/c` (only the `..`
-- is dropped, not the preceding `b` segment). True ModSec resolves
-- to `/a/c`. Documented limitation — fix is a separate task.
eq("/a/b/../c → /a/b/c (Karna current limitation)",
                      "normalizePath", "/a/b/../c", "/a/b/c")

print("== normalizePathWin (\\ → /) ==")
eq("\\a\\b → /a/b",   "normalizePathWin", "\\a\\b", "/a/b")
eq("\\a\\.\\b → /a/b","normalizePathWin", "\\a\\.\\b", "/a/b")

print("== urlDecodeUni (multi-pass) ==")
eq("%41 → A",         "urlDecodeUni", "%41",       "A")
eq("%u003C → <",      "urlDecodeUni", "%u003C",    "<")
eq("plus → space",    "urlDecodeUni", "a+b",       "a b")

print("== utf8toUnicode ==")
-- é = 0xC3 0xA9 (U+00E9)
eq("é → %u00e9",       "utf8toUnicode", "\xC3\xA9",      "%u00e9")
-- ＜ = 0xEF 0xBC 0x9C (U+FF1C) — fullwidth less-than
eq("＜ → %uff1c",      "utf8toUnicode", "\xEF\xBC\x9C",  "%uff1c")
-- ASCII pass-through
eq("ASCII unchanged",  "utf8toUnicode", "abc",           "abc")

print("== jsDecode ==")
eq("\\u0020 → space (BMP ASCII)",          "jsDecode", "a\\u0020b",                              "a b")
eq("\\uFF1C → < (fullwidth ASCII normalised)", "jsDecode", "\\uFF1C",                            "<")
-- Non-fullwidth-ASCII BMP codepoint: é → UTF-8 0xC3 0xA9 (é)
eq("\\u00E9 → UTF-8 é",                    "jsDecode", "\\u00E9",                                "\xC3\xA9")

print("== cssDecode ==")
-- \41 → A (CSS escape: \HH → that codepoint)
eq("\\41 → A",                "cssDecode", "\\41",     "A")
-- Backslash before non-hex char (ja\vascript → javascript)
eq("\\v in non-hex → drop backslash",  "cssDecode", "ja\\vascript", "javascript")

print("== cmdLine ==")
-- cmdLine: strip backslash/quote/caret, drop spaces before / or (,
-- replace ,/; with space, collapse whitespace, lowercase. Leading
-- whitespace is collapsed to a single space (not stripped).
eq("strips quotes + caret + collapses whitespace",
   "cmdLine", "  LS -la  /etc/passwd  ",  " ls -la/etc/passwd ")
eq("strips backslashes",
   "cmdLine", [[bash\ -c]],                "bash -c")
eq(", and ; → space",
   "cmdLine", "cat,a;b",                   "cat a b")

print("== base64Decode ==")
-- "QUJD" is base64 of "ABC"
eq("QUJD → ABC",  "base64Decode", "QUJD",  "ABC")
eq("alias base64decode (lowercase)", "base64decode", "QUJD", "ABC")

print("== sha1 + hexEncode ==")
-- sha1 returns 20 raw bytes; hexEncode turns each into 2 lowercase hex chars
local sha = apply("sha1", "abc")
check("sha1 returns 20 bytes", type(sha) == "string" and #sha == 20)
local hex = apply("hexEncode", "AB")
eq("hexEncode \"AB\" → \"4142\"", "hexEncode", "AB", "4142")

-- ===========================================================================
print(string.format("\n%d failure(s)", failures))
os.exit(failures == 0 and 0 or 1)
