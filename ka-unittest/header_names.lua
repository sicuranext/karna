-- ka-unittest/header_names.lua
--
-- Tests for ka_header_names: request header NAMES for the audit log, in wire
-- order and casing on HTTP/1.x ("raw"), lowercase-sorted on HTTP/2
-- ("normalized"). Plain assertions, no luaunit, runs on Lua 5.1 / LuaJIT / 5.4.
-- Run from repo root:   lua ka-unittest/header_names.lua

package.path = "./kong/plugins/karna/modules/?.lua;" .. package.path

local ok, hn = pcall(require, "ka_header_names")
if not ok then
    io.stderr:write("FAIL: cannot load ka_header_names.lua: " .. tostring(hn) .. "\n")
    os.exit(1)
end

local failures = 0
local function check(label, cond)
    if cond then print("  PASS  " .. label) else print("  FAIL  " .. label); failures = failures + 1 end
end
local function same(a, b)
    if #a ~= #b then return false end
    for i = 1, #a do if a[i] ~= b[i] then return false end end
    return true
end
local function join(t) return table.concat(t, ",") end

-- parse_raw -----------------------------------------------------------------
print("parse_raw")
local raw = "Host: example.com\r\nUser-Agent: curl/8.7.1\r\nX-Custom-Header: 1\r\n"
         .. "x-custom-header: 2\r\nAccept: text/html\r\nAccept: application/json\r\n"
         .. "X-Last: end\r\n\r\n"
local names, trunc = hn.parse_raw(raw)
check("order preserved, casing preserved, duplicates kept",
      same(names, {"Host","User-Agent","X-Custom-Header","x-custom-header","Accept","Accept","X-Last"}))
check("not truncated", trunc == false)

names = hn.parse_raw("Host: a\nAccept: b\n")
check("LF-only line endings tolerated", same(names, {"Host","Accept"}))

names = hn.parse_raw("Host: a\r\n Folded: continuation\r\n\tAlso: folded\r\nAccept: b\r\n")
check("obs-fold continuation lines are not header names", same(names, {"Host","Accept"}))

names = hn.parse_raw("Host: a\r\nno-colon-here\r\n: empty-name\r\nAccept: b\r\n")
check("lines without a name are skipped", same(names, {"Host","Accept"}))

names = hn.parse_raw("Host:nospace\r\nX-Empty:\r\n")
check("no space after colon / empty value still yield the name", same(names, {"Host","X-Empty"}))

names = hn.parse_raw("Host: a")
check("last line without CRLF is parsed", same(names, {"Host"}))

check("empty string → empty list", #hn.parse_raw("") == 0)
check("nil → empty list", #hn.parse_raw(nil) == 0)
check("non-string → empty list", #hn.parse_raw(42) == 0)

local long = string.rep("A", 300)
names = hn.parse_raw(long .. ": v\r\n")
check("name longer than 256 bytes is clipped to 256", #names[1] == 256)

local many = {}
for i = 1, 130 do many[#many + 1] = "H" .. i .. ": v" end
names, trunc = hn.parse_raw(table.concat(many, "\r\n") .. "\r\n")
check("more than 128 headers → first 128 kept", #names == 128 and names[1] == "H1" and names[128] == "H128")
check("truncation flagged", trunc == true)

names = hn.parse_raw("A: 1\r\nB: 2\r\nC: 3\r\n", 2)
check("custom max_names honoured", same(names, {"A","B"}))

-- from_table -----------------------------------------------------------------
print("from_table")
names, trunc = hn.from_table({ ["Host"] = "h", ["User-Agent"] = "ua", ["Accept"] = {"a","b"},
                               ["x-custom-header"] = {"1","2"} })
check("lowercase, sorted, repeated per value",
      same(names, {"accept","accept","host","user-agent","x-custom-header","x-custom-header"}))
check("not truncated", trunc == false)

names = hn.from_table({ ["X-Empty-Table"] = {} , ["Host"] = "h" })
check("empty multi-value table still counts once", same(names, {"host","x-empty-table"}))

names = hn.from_table({ [1] = "positional", ["Host"] = "h" })
check("non-string keys ignored", same(names, {"host"}))

local big = {}
for i = 1, 200 do big["h" .. string.format("%03d", i)] = "v" end
names, trunc = hn.from_table(big)
check("capped at 128 after sorting", #names == 128 and names[1] == "h001" and names[128] == "h128")
check("truncation flagged", trunc == true)

check("nil table → empty list", #hn.from_table(nil) == 0)

-- capture (fake ngx.req) --------------------------------------------------------
print("capture")
local fake_h1 = {
    raw_header  = function(no_req_line) assert(no_req_line == true); return "Host: a\r\nX-A: 1\r\nx-a: 2\r\n" end,
    get_headers = function() error("must not be called on the raw path") end,
}
local mode, truncated
names, mode, truncated = hn.capture(fake_h1)
check("HTTP/1.x → raw mode", mode == "raw")
check("HTTP/1.x → wire names", same(names, {"Host","X-A","x-a"}))
check("HTTP/1.x → not truncated", truncated == false)

local fake_h2 = {
    raw_header  = function() error("http2 requests not supported yet") end,
    get_headers = function(max, rawflag) assert(max == 0 and rawflag == true)
                     return { host = "a", ["x-a"] = {"1","2"}, accept = "b" } end,
}
names, mode, truncated = hn.capture(fake_h2)
check("HTTP/2 → normalized mode", mode == "normalized")
check("HTTP/2 → lowercase sorted repeated", same(names, {"accept","host","x-a","x-a"}))

local fake_broken = {
    raw_header  = function() error("boom") end,
    get_headers = function() error("boom too") end,
}
names, mode = hn.capture(fake_broken)
check("both paths failing → empty normalized list, no throw", mode == "normalized" and #names == 0)

local fake_raw_nonstring = {
    raw_header  = function() return nil end,
    get_headers = function() return { host = "a" } end,
}
names, mode = hn.capture(fake_raw_nonstring)
check("raw_header returning nil falls back to normalized", mode == "normalized" and same(names, {"host"}))

names, mode = hn.capture(nil)
check("no ngx at all → empty normalized list", mode == "normalized" and #names == 0)

names, mode, truncated = hn.capture(fake_h1, 2)
check("capture forwards max_names", #names == 2 and truncated == true)

-- determinism ------------------------------------------------------------------
print("determinism")
local a = hn.from_table({ b = "1", a = "2", c = {"x","y"} })
local b = hn.from_table({ c = {"x","y"}, a = "2", b = "1" })
check("same header set, different insertion order → same list", join(a) == join(b))

if failures > 0 then
    io.stderr:write(("\n%d failure(s)\n"):format(failures))
    os.exit(1)
end
print("\nall green")
