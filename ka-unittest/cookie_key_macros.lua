-- ka-unittest/cookie_key_macros.lua
--
-- Guards the per-client Redis key macros:
--
--   %{request_cookies.<name>}       one request cookie, read off the Cookie header
--   %{response_set_cookie.<name>}   one response Set-Cookie value (header_filter on)
--   %{sha256:<macro>}               lowercase hex SHA-256 of any key macro
--
-- A rule pair "mark in one request, check in a later one" (header_filter
-- `redis_set` on `cart:<session cookie>:t`, access `redis.cart:<session
-- cookie>:t` with isSet) needs the write side and the read side to build the
-- same key in every phase. And a request WITHOUT the cookie must never build a
-- key at all: a key holding "" or the literal macro would be shared by every
-- cookieless client. So the write is skipped and the read is "unknown", which
-- matches neither `isSet` nor `!isSet`.
--
-- What is pinned here, through the REAL engine:
--   1. write resolver == read resolver for the cookie macro, in access and in
--      header_filter;
--   2. cookie names are case-insensitive, the first duplicate wins, the value
--      is raw;
--   3. Set-Cookie: attributes dropped, several headers, last one wins, absent
--      in access;
--   4. sha256 output (known vector, lowercase hex), also on the older macros;
--   5. absent cookie: redis_set / redis_sadd / redis_del / redis_incr_key are
--      skipped, and the redis.<key> read matches neither isSet form, whatever
--      redis_on_error says;
--   6. long values are capped at 256 bytes, hashed values are hashed whole;
--   7. %{request_headers.X} keeps its historical "" on a missing header.
--
-- Fixtures are synthetic. Lua 5.4 (the SHA-256 stand-in uses integer bit ops).
--
-- Run from repo root:
--   lua ka-unittest/cookie_key_macros.lua

-- ---------------------------------------------------------------------------
-- pure-Lua SHA-256 behind the resty.sha256 / resty.string interface
-- ---------------------------------------------------------------------------
local function sha256_bin(msg)
    local k = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
    }
    local M = 0xffffffff
    local function rotr(x, n) return ((x >> n) | (x << (32 - n))) & M end
    local h = { 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 }
    local len = #msg
    msg = msg .. "\128" .. string.rep("\0", (55 - len) % 64) .. string.pack(">I8", len * 8)
    for chunk = 1, #msg, 64 do
        local w = {}
        for i = 0, 15 do w[i] = string.unpack(">I4", msg, chunk + i * 4) end
        for i = 16, 63 do
            local s0 = rotr(w[i-15], 7) ~ rotr(w[i-15], 18) ~ (w[i-15] >> 3)
            local s1 = rotr(w[i-2], 17) ~ rotr(w[i-2], 19) ~ (w[i-2] >> 10)
            w[i] = (w[i-16] + s0 + w[i-7] + s1) & M
        end
        local a, b, c, d, e, f, g, hh = table.unpack(h)
        for i = 0, 63 do
            local S1 = rotr(e, 6) ~ rotr(e, 11) ~ rotr(e, 25)
            local ch = (e & f) ~ ((~e) & g)
            local t1 = (hh + S1 + ch + k[i+1] + w[i]) & M
            local S0 = rotr(a, 2) ~ rotr(a, 13) ~ rotr(a, 22)
            local maj = (a & b) ~ (a & c) ~ (b & c)
            local t2 = (S0 + maj) & M
            hh, g, f, e, d, c, b, a = g, f, e, (d + t1) & M, c, b, a, (t1 + t2) & M
        end
        local add = { a, b, c, d, e, f, g, hh }
        for i = 1, 8 do h[i] = (h[i] + add[i]) & M end
    end
    local out = {}
    for i = 1, 8 do out[i] = string.pack(">I4", h[i]) end
    return table.concat(out)
end

package.preload["resty.sha256"] = function()
    local S = {}
    S.__index = S
    function S.new(_) return setmetatable({ buf = {} }, S) end
    function S:update(s) self.buf[#self.buf + 1] = s; return true end
    function S:final() return sha256_bin(table.concat(self.buf)) end
    return S
end
package.preload["resty.string"] = function()
    return { to_hex = function(s) return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end)) end }
end

local H = dofile("./ka-unittest/_engine_harness.lua")
local engine = H.engine
local utils  = require "kong.plugins.karna.ka_utils"

local fails = 0
local function ok(cond, name, detail)
    if cond then print("  ok  - " .. name)
    else print("  FAIL- " .. name .. (detail and ("  (" .. tostring(detail) .. ")") or "")); fails = fails + 1 end
end
local function eq(got, want, name)
    ok(got == want, name, "got " .. tostring(got) .. ", want " .. tostring(want))
end

-- phase + response headers, switchable per case
local PHASE = "access"
local RESPONSE_HEADERS = {}
ngx.get_phase = function() return PHASE end
kong.response.get_headers = function()
    if PHASE == "access" then error("kong.response.get_headers is not callable in access") end
    return RESPONSE_HEADERS
end

local SID = "c2Vzc2lvbi1zeW50aGV0aWMtMDAx"
local function request_with(cookie_header, phase)
    H.reset()
    PHASE = phase or "access"
    RESPONSE_HEADERS = {}
    H.request.method  = "GET"
    H.request.path    = "/cart"
    H.request.headers = { Host = "app.example", Cookie = cookie_header }
    kong.ctx.plugin.inspection_table = nil
end

-- Redis read / write capture. `utils` is the table the engine holds.
local READS, WRITES, INCRS = {}, {}, {}
local STORE = {}
utils.redis_inspect_read = function(_, _, cmd, key, member)
    READS[#READS + 1] = { cmd = cmd, key = key }
    if cmd == "exists" then return STORE[key] and 1 or 0 end
    if cmd == "get" then return STORE[key] or ngx.null end
    return 0
end
utils.redis_write = function(_, _, op, key, arg, ttl)
    WRITES[#WRITES + 1] = { op = op, key = key, arg = arg, ttl = ttl }
    if op == "set" then STORE[key] = arg elseif op == "del" then STORE[key] = nil end
    return true
end
utils.redis_incr_key = function(_, _, key, expire)
    INCRS[#INCRS + 1] = { key = key, expire = expire }
    return #INCRS
end
local real_timer_at = ngx.timer.at
-- header_filter writes are deferred to a timer: run them inline
ngx.timer.at = function(_, fn, ...) fn(false, ...); return true end
local function clear_io() READS, WRITES, INCRS = {}, {}, {} end

local plugin_conf = {
    engine_fast_path = true,
    redis_inspect_enabled = true,
    redis_host = "127.0.0.1", redis_port = 6379,
}

local function isset_rule(key_template, negated)
    return {
        id = "cart-check", phase = "access",
        conditions = { { variables = { "redis." .. key_template }, op = "isSet", negated = negated or false } },
    }
end

local function matched(rule, conf)
    return engine:__match_rule_conditions(rule, conf or plugin_conf) == true
end

-- ---------------------------------------------------------------------------
-- 1. write == read, access and header_filter
-- ---------------------------------------------------------------------------
print("\n-- request_cookies: write and read agree on one key --")

request_with("theme=dark; sid=" .. SID .. "; lang=en")
eq(engine:__resolve_redis_key_macros("cart:%{request_cookies.sid}:t"), "cart:" .. SID .. ":t",
   "access: the cookie macro resolves to the one cookie value")
eq(select(2, engine:__resolve_redis_key_macros("cart:%{request_cookies.sid}:t")), false,
   "access: a present cookie does not set the absent flag")
eq(engine:replace_variable_in_string("cart:%{request_cookies.sid}:t"), "cart:" .. SID .. ":t",
   "pass 1 of replace_variable_in_string produces the same key")

-- header_filter write, then access read on a later request
STORE = {}
request_with("sid=" .. SID, "header_filter")
clear_io()
engine:apply_action_side_effects({
    id = "cart-mark", phase = "header_filter",
    action = { redis_set = { key = "cart:%{request_cookies.sid}:t", expire = 900 } },
}, plugin_conf, "header_filter")
eq(WRITES[1] and WRITES[1].key, "cart:" .. SID .. ":t", "header_filter: redis_set writes the cookie-keyed key")
eq(WRITES[1] and WRITES[1].ttl, 900, "header_filter: the expire is passed through")

request_with("sid=" .. SID)
clear_io()
ok(matched(isset_rule("cart:%{request_cookies.sid}:t")), "access: isSet on the same template finds the mark")
eq(READS[1] and READS[1].key, "cart:" .. SID .. ":t", "access: the read looked up the written key")
ok(not matched(isset_rule("cart:%{request_cookies.sid}:t", true)), "access: negated isSet does not match when the mark exists")

request_with("sid=another-session-value")
ok(not matched(isset_rule("cart:%{request_cookies.sid}:t")), "another session: isSet does not match")
ok(matched(isset_rule("cart:%{request_cookies.sid}:t", true)), "another session: negated isSet matches")

-- redis_incr_key in access, then the ge read
request_with("chal=ch-001")
clear_io()
engine:apply_action_side_effects({
    id = "chal-count", phase = "access",
    action = { redis_incr_key = { key = "chal:%{request_cookies.chal}", expire = 60 } },
}, plugin_conf, "access")
eq(INCRS[1] and INCRS[1].key, "chal:ch-001", "access: redis_incr_key increments the cookie-keyed counter")
eq(INCRS[1] and INCRS[1].key, engine:__resolve_redis_key_macros("chal:%{request_cookies.chal}"),
   "the incremented key is the key the redis.<key> reader derives")

-- ---------------------------------------------------------------------------
-- 2. name matching and duplicates
-- ---------------------------------------------------------------------------
print("\n-- request_cookies: names, duplicates, raw value --")

request_with("SID=upper-case-name")
eq(engine:__resolve_redis_key_macros("%{request_cookies.sid}"), "upper-case-name",
   "cookie name in the header is matched case-insensitively")
eq(engine:__resolve_redis_key_macros("%{request_cookies.SiD}"), "upper-case-name",
   "cookie name in the macro is matched case-insensitively")

request_with("sid=first; sid=second")
eq(engine:__resolve_redis_key_macros("%{request_cookies.sid}"), "first", "duplicate cookie: first occurrence wins")

request_with("a=1;; ; sid=v%3D1 ;")
eq(engine:__resolve_redis_key_macros("%{request_cookies.sid}"), "v%3D1",
   "empty segments are skipped, the value is raw (no %HH decoding) and trimmed")

request_with("xsid=nope; sidx=nope")
local v, absent = engine:__resolve_redis_key_macros("k:%{request_cookies.sid}")
ok(absent == true, "a cookie whose name only CONTAINS the wanted name does not match")

-- ---------------------------------------------------------------------------
-- 3. response_set_cookie
-- ---------------------------------------------------------------------------
print("\n-- response_set_cookie --")

request_with(nil, "header_filter")
RESPONSE_HEADERS = { ["set-cookie"] = "sid=" .. SID .. "; Path=/; HttpOnly; SameSite=Lax" }
eq(engine:__resolve_redis_key_macros("sid:%{response_set_cookie.sid}"), "sid:" .. SID,
   "single Set-Cookie: value up to the first ';', attributes dropped")

RESPONSE_HEADERS = { ["Set-Cookie"] = {
    "theme=dark; Path=/",
    "SID=old; Max-Age=60",
    "sid=" .. SID .. "; Secure",
} }
eq(engine:__resolve_redis_key_macros("%{response_set_cookie.sid}"), SID,
   "several Set-Cookie headers: the matching one, the last when repeated, name case-insensitive")

RESPONSE_HEADERS = { ["set-cookie"] = "sid=; Max-Age=0; Path=/" }
v, absent = engine:__resolve_redis_key_macros("%{response_set_cookie.sid}")
ok(absent == true, "a deletion Set-Cookie (empty value) is absent")

RESPONSE_HEADERS = { ["set-cookie"] = "theme=dark" }
v, absent = engine:__resolve_redis_key_macros("%{response_set_cookie.sid}")
ok(absent == true, "no Set-Cookie with that name is absent")

-- write from header_filter
clear_io()
RESPONSE_HEADERS = { ["set-cookie"] = { "sid=" .. SID .. "; Path=/" } }
engine:apply_action_side_effects({
    id = "sid-mark", phase = "header_filter",
    action = { redis_set = { key = "sid:%{response_set_cookie.sid}", expire = 3600 } },
}, plugin_conf, "header_filter")
eq(WRITES[1] and WRITES[1].key, "sid:" .. SID, "header_filter: redis_set keyed on the Set-Cookie value")

request_with("sid=" .. SID, "access")
v, absent = engine:__resolve_redis_key_macros("sid:%{response_set_cookie.sid}")
ok(absent == true, "access: response_set_cookie is absent (no response yet), and nothing errors")
eq(engine:__resolve_redis_key_macros("sid:%{request_cookies.sid}"), "sid:" .. SID,
   "the later request reads the same key through request_cookies")

-- ---------------------------------------------------------------------------
-- 4. sha256
-- ---------------------------------------------------------------------------
print("\n-- sha256 modifier --")

request_with("sid=abc")
eq(engine:__resolve_redis_key_macros("%{sha256:request_cookies.sid}"),
   "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
   "sha256 of a cookie value: known vector, lowercase hex")
eq(engine:__resolve_redis_key_macros("cart:%{sha256:request_cookies.sid}:t"),
   "cart:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad:t",
   "hashed segment inside a key")

H.request.headers["X-Session"] = "abc"
eq(engine:__resolve_redis_key_macros("%{sha256:request_headers.x-session}"),
   "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
   "sha256 on the existing request_headers macro")
eq(engine:__resolve_redis_key_macros("%{sha256:remote_addr}"), engine._sha256_hex("192.0.2.10"),
   "sha256 on remote_addr")
v, absent = engine:__resolve_redis_key_macros("%{sha256:request_headers.x-missing}")
ok(absent == true, "sha256 of a missing header is absent (new syntax, new rule)")
v, absent = engine:__resolve_redis_key_macros("%{sha256:no.such.macro}")
ok(absent == true, "sha256 of an unknown macro is absent, never a shared key")

-- header_filter write + access read agree on the hashed key
STORE = {}
request_with("sid=" .. SID, "header_filter")
clear_io()
engine:apply_action_side_effects({
    id = "cart-mark", phase = "header_filter",
    action = { redis_set = { key = "cart:%{sha256:request_cookies.sid}:t", expire = 900 } },
}, plugin_conf, "header_filter")
ok(WRITES[1] and not WRITES[1].key:find(SID, 1, true), "the session id does not appear in clear in the key")
request_with("sid=" .. SID)
ok(matched(isset_rule("cart:%{sha256:request_cookies.sid}:t")), "the hashed mark is found by the hashed read")

-- ---------------------------------------------------------------------------
-- 5. absent cookie
-- ---------------------------------------------------------------------------
print("\n-- absent cookie: no write, the read never matches --")

for _, header in ipairs({ "", "theme=dark", "sid=", "sid" }) do
    request_with(header ~= "" and header or nil)
    clear_io()
    engine:apply_action_side_effects({
        id = "w", phase = "access",
        action = {
            redis_set  = { key = "cart:%{request_cookies.sid}:t", expire = 900 },
            redis_sadd = { key = "sessions", member = "%{request_cookies.sid}" },
            redis_del  = { key = "cart:%{sha256:request_cookies.sid}:t" },
            redis_incr_key = { key = "chal:%{request_cookies.sid}", expire = 60 },
        },
    }, plugin_conf, "access")
    eq(#WRITES + #INCRS, 0, "Cookie '" .. header .. "': no redis write of any kind")

    for _, on_error in ipairs({ "skip", "fail_open", "fail_closed" }) do
        local conf = {}
        for k2, v2 in pairs(plugin_conf) do conf[k2] = v2 end
        conf.redis_on_error = on_error
        request_with(header ~= "" and header or nil)
        clear_io()
        ok(not matched(isset_rule("cart:%{request_cookies.sid}:t"), conf),
           "Cookie '" .. header .. "', " .. on_error .. ": isSet does not match")
        request_with(header ~= "" and header or nil)
        ok(not matched(isset_rule("cart:%{request_cookies.sid}:t", true), conf),
           "Cookie '" .. header .. "', " .. on_error .. ": negated isSet does not match")
        eq(#READS, 0, "Cookie '" .. header .. "', " .. on_error .. ": Redis is never asked")
    end
end

-- the same through the legacy "!isSet" spelling
request_with(nil)
ok(not matched({ id = "x", phase = "access",
    conditions = { { variables = { "redis.cart:%{request_cookies.sid}:t" }, op = "!isSet" } } }),
   "legacy !isSet spelling does not match either")

-- a value operator (GET) also stays silent
request_with(nil)
clear_io()
ok(not matched({ id = "x", phase = "access",
    conditions = { { variables = { "redis.chal:%{request_cookies.chal}" }, op = "ge", value = "2" } } }),
   "ge on an absent cookie key does not match")
eq(#READS, 0, "ge: Redis is never asked")

-- ---------------------------------------------------------------------------
-- 6. length cap
-- ---------------------------------------------------------------------------
print("\n-- length cap --")

local long = string.rep("A", 300) .. "TAIL"
request_with("sid=" .. long)
local plain = engine:__resolve_redis_key_macros("%{request_cookies.sid}")
eq(#plain, engine.KEY_MACRO_VALUE_CAP, "a long cookie value is capped at 256 bytes")
eq(plain, string.sub(long, 1, 256), "the cap keeps the leading bytes")
eq(engine:__resolve_redis_key_macros("%{sha256:request_cookies.sid}"), engine._sha256_hex(long),
   "the hashed form hashes the WHOLE value")

-- ---------------------------------------------------------------------------
-- 7. request_headers keeps its historical behaviour
-- ---------------------------------------------------------------------------
print("\n-- request_headers unchanged --")

request_with(nil)
local hv, habsent = engine:__resolve_redis_key_macros("acl:%{request_headers.x-consumer-id}")
eq(hv, "acl:", "a missing header still resolves to \"\"")
eq(habsent, false, "and does not set the absent flag")

-- a cookie value that looks like a macro is not expanded again
request_with("sid=%{remote_addr}")
eq(engine:__resolve_redis_key_macros("k:%{request_cookies.sid}"), "k:%{remote_addr}",
   "a resolved cookie value is not re-scanned for macros")

ngx.timer.at = real_timer_at

print("")
print(fails .. " test(s) failed")
os.exit(fails == 0 and 0 or 1)
