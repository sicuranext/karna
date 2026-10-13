-- ka-unittest/arg_key_macros.lua
--
-- Guards the request-argument Redis key macros and the redis_set NX option:
--
--   %{request.query.value:<name>}           one query-string argument
--   %{request.body.urlencode.value:<name>}  one urlencoded body argument
--   %{sha256:<either of them>}
--
-- Each macro reads ONE source, the same key the rule variable of that name
-- reads. There is no ARGS-style macro: a key built from "whichever source has
-- the argument" would let a client move it and land on another key.
--
-- What is pinned here, through the REAL engine:
--   1. write resolver == read resolver (redis_set, redis_incr_key, redis.<key>);
--   2. source separation: a query argument never fills the body macro, and
--      the other way round;
--   3. names case-insensitive, first occurrence wins, value decoded;
--   4. absent: missing, empty, name-only, non-urlencoded body, body switched
--      off -> no write of any kind, and the read matches neither isSet form;
--   5. long values capped at 256 bytes, hashed values hashed whole;
--   6. a resolved value is not re-scanned for macros;
--   7. redis_set nx: passed through to redis_write, default off.
--
-- Fixtures are synthetic. Lua 5.4 (the SHA-256 stand-in uses integer bit ops).
--
-- Run from repo root:
--   lua ka-unittest/arg_key_macros.lua

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

local function request_with(raw_query, body, content_type)
    H.reset()
    H.request.method    = body and "POST" or "GET"
    H.request.path      = "/cart/edit"
    H.request.raw_path  = "/cart/edit"
    H.request.raw_query = raw_query or ""
    H.request.headers   = { Host = "app.example" }
    if body then
        H.request.headers["Content-Type"]   = content_type or "application/x-www-form-urlencoded"
        H.request.headers["Content-Length"] = tostring(#body)
    end
    H.request.body = body
end

local READS, WRITES, INCRS = {}, {}, {}
local STORE = {}
utils.redis_inspect_read = function(_, _, cmd, key)
    READS[#READS + 1] = { cmd = cmd, key = key }
    if cmd == "exists" then return STORE[key] and 1 or 0 end
    if cmd == "get" then return STORE[key] or ngx.null end
    return 0
end
utils.redis_write = function(_, _, op, key, arg, ttl, nx)
    WRITES[#WRITES + 1] = { op = op, key = key, arg = arg, ttl = ttl, nx = nx }
    if op == "set" and not (nx and STORE[key]) then STORE[key] = arg end
    return true
end
utils.redis_incr_key = function(_, _, key, expire)
    INCRS[#INCRS + 1] = { key = key, expire = expire }
    STORE[key] = tostring((tonumber(STORE[key]) or 0) + 1)
    return tonumber(STORE[key])
end
local function clear_io() READS, WRITES, INCRS = {}, {}, {} end

local plugin_conf = {
    engine_fast_path = true,
    redis_inspect_enabled = true,
    redis_host = "127.0.0.1", redis_port = 6379,
}

local function cond_rule(key_template, op, negated, value)
    return {
        id = "line-check", phase = "access",
        conditions = { { variables = { "redis." .. key_template }, op = op, negated = negated or false, value = value } },
    }
end
local function matched(rule, conf)
    return engine:__match_rule_conditions(rule, conf or plugin_conf) == true
end
local function side_effects(action)
    engine:apply_action_side_effects({ id = "w", phase = "access", action = action }, plugin_conf, "access")
end

local LINE = "6f1c2a8e-0b7d-4c55-9a43-2f0e8d1b7c90"
local BODY = "action=edit&line_id=" .. LINE .. "&quantity=2"

-- ---------------------------------------------------------------------------
print("\n-- 1. write and read agree on one key --")
-- ---------------------------------------------------------------------------
STORE = {}
request_with(nil, BODY)
eq(engine:__resolve_redis_key_macros("line:%{request.body.urlencode.value:line_id}"), "line:" .. LINE,
   "body macro resolves to the urlencoded argument")
eq(select(2, engine:__resolve_redis_key_macros("line:%{request.body.urlencode.value:line_id}")), false,
   "a present argument does not set the absent flag")
eq(engine:replace_variable_in_string("line:%{request.body.urlencode.value:line_id}"), "line:" .. LINE,
   "pass 1 of replace_variable_in_string produces the same key")

clear_io()
side_effects({ redis_incr_key = { key = "line:n:%{sha256:request.body.urlencode.value:line_id}", expire = 1800 } })
eq(INCRS[1] and INCRS[1].key, "line:n:" .. engine._sha256_hex(LINE), "redis_incr_key uses the hashed argument")

request_with(nil, BODY)
side_effects({ redis_incr_key = { key = "line:n:%{sha256:request.body.urlencode.value:line_id}", expire = 1800 } })
request_with(nil, BODY)
side_effects({ redis_incr_key = { key = "line:n:%{sha256:request.body.urlencode.value:line_id}", expire = 1800 } })
request_with(nil, BODY)
clear_io()
ok(matched(cond_rule("line:n:%{sha256:request.body.urlencode.value:line_id}", "gt", false, "2")),
   "the counter read back with gt matches after three increments")
eq(READS[1] and READS[1].key, INCRS[1] and INCRS[1].key or ("line:n:" .. engine._sha256_hex(LINE)),
   "the read looked up the incremented key")
ok(not matched(cond_rule("line:n:%{sha256:request.body.urlencode.value:line_id}", "gt", false, "3")),
   "gt 3 does not match a counter at 3")

request_with("line_id=" .. LINE)
eq(engine:__resolve_redis_key_macros("line:%{request.query.value:line_id}"), "line:" .. LINE,
   "query macro resolves to the query-string argument")

-- ---------------------------------------------------------------------------
print("\n-- 2. one macro, one source --")
-- ---------------------------------------------------------------------------
request_with("line_id=from-query", "line_id=from-body")
eq(engine:__resolve_redis_key_macros("%{request.query.value:line_id}"), "from-query", "query macro reads the query")
eq(engine:__resolve_redis_key_macros("%{request.body.urlencode.value:line_id}"), "from-body", "body macro reads the body")

request_with("line_id=" .. LINE, "action=edit")
local v, absent = engine:__resolve_redis_key_macros("%{request.body.urlencode.value:line_id}")
ok(absent == true, "argument only in the query: the body macro is absent, no fallback")
request_with(nil, BODY)
v, absent = engine:__resolve_redis_key_macros("%{request.query.value:line_id}")
ok(absent == true, "argument only in the body: the query macro is absent, no fallback")

v, absent = engine:__resolve_redis_key_macros("%{ARGS.line_id}")
eq(v, "%{ARGS.line_id}", "there is no ARGS key macro: it stays literal")
v, absent = engine:__resolve_redis_key_macros("%{request.arg.value:line_id}")
eq(v, "%{request.arg.value:line_id}", "request.arg.value is not a key macro either")

-- ---------------------------------------------------------------------------
print("\n-- 3. names, duplicates, decoding --")
-- ---------------------------------------------------------------------------
request_with(nil, "Line_ID=mixed")
eq(engine:__resolve_redis_key_macros("%{request.body.urlencode.value:line_id}"), "mixed",
   "argument name in the body is matched case-insensitively")
eq(engine:__resolve_redis_key_macros("%{request.body.urlencode.value:LINE_id}"), "mixed",
   "argument name in the macro is matched case-insensitively")

request_with("line_id=first&line_id=second")
eq(engine:__resolve_redis_key_macros("%{request.query.value:line_id}"), "first", "repeated query argument: first wins")
request_with(nil, "line_id=first&line_id=second")
eq(engine:__resolve_redis_key_macros("%{request.body.urlencode.value:line_id}"), "first", "repeated body argument: first wins")

request_with(nil, "line_id=a%20b%2Bc")
eq(engine:__resolve_redis_key_macros("%{request.body.urlencode.value:line_id}"), "a b+c",
   "the value is the decoded one the rule variable sees")

request_with(nil, "xline_id=nope&line_idx=nope")
v, absent = engine:__resolve_redis_key_macros("%{request.body.urlencode.value:line_id}")
ok(absent == true, "an argument whose name only CONTAINS the wanted name does not match")

-- ---------------------------------------------------------------------------
print("\n-- 4. absent: no write, the read never matches --")
-- ---------------------------------------------------------------------------
local ABSENT_CASES = {
    { "missing",               nil, "action=edit&quantity=2" },
    { "empty value",           nil, "line_id=&quantity=2" },
    { "name only",             nil, "line_id&quantity=2" },
    { "no body",               nil, nil },
    { "JSON body",             nil, '{"line_id":"' .. LINE .. '"}', "application/json" },
    { "multipart body",        nil, "--b\r\nContent-Disposition: form-data; name=\"line_id\"\r\n\r\n" .. LINE .. "\r\n--b--\r\n",
                                    "multipart/form-data; boundary=b" },
    { "body switched off",     nil, BODY, nil, true },
}
local TEMPLATE = "line:%{sha256:request.body.urlencode.value:line_id}"
for _, c in ipairs(ABSENT_CASES) do
    local name, q, body, ct, off = c[1], c[2], c[3], c[4], c[5]
    request_with(q, body, ct)
    kong.ctx.plugin.rule_controls.body_access_off = off or false
    clear_io()
    side_effects({
        redis_set      = { key = TEMPLATE, expire = 1800, nx = true },
        redis_sadd     = { key = "lines", member = "%{request.body.urlencode.value:line_id}" },
        redis_del      = { key = TEMPLATE },
        redis_incr_key = { key = TEMPLATE, expire = 60 },
    })
    eq(#WRITES + #INCRS, 0, name .. ": no redis write of any kind")
    for _, on_error in ipairs({ "skip", "fail_open", "fail_closed" }) do
        local conf = {}
        for k2, v2 in pairs(plugin_conf) do conf[k2] = v2 end
        conf.redis_on_error = on_error
        request_with(q, body, ct)
        kong.ctx.plugin.rule_controls.body_access_off = off or false
        clear_io()
        ok(not matched(cond_rule(TEMPLATE, "isSet"), conf), name .. ", " .. on_error .. ": isSet does not match")
        request_with(q, body, ct)
        kong.ctx.plugin.rule_controls.body_access_off = off or false
        ok(not matched(cond_rule(TEMPLATE, "isSet", true), conf), name .. ", " .. on_error .. ": negated isSet does not match")
        eq(#READS, 0, name .. ", " .. on_error .. ": Redis is never asked")
    end
end

request_with(nil, "action=edit")
v, absent = engine:__resolve_redis_key_macros("%{request.query.value:line_id}")
ok(absent == true, "query macro with no query string is absent")

-- ---------------------------------------------------------------------------
print("\n-- 5. length cap --")
-- ---------------------------------------------------------------------------
local long = string.rep("A", 300) .. "TAIL"
request_with(nil, "line_id=" .. long)
local plain = engine:__resolve_redis_key_macros("%{request.body.urlencode.value:line_id}")
eq(#plain, engine.KEY_MACRO_VALUE_CAP, "a long argument value is capped at 256 bytes")
eq(engine:__resolve_redis_key_macros("%{sha256:request.body.urlencode.value:line_id}"), engine._sha256_hex(long),
   "the hashed form hashes the WHOLE value")
request_with(nil, "line_id=abc")
eq(engine:__resolve_redis_key_macros("%{sha256:request.body.urlencode.value:line_id}"),
   "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "sha256 known vector")

-- ---------------------------------------------------------------------------
print("\n-- 6. a resolved value is not re-scanned --")
-- ---------------------------------------------------------------------------
request_with("line_id=%25%7Bremote_addr%7D")
eq(engine:__resolve_redis_key_macros("k:%{request.query.value:line_id}"), "k:%{remote_addr}",
   "an argument value that looks like a macro is not expanded again")

-- ---------------------------------------------------------------------------
print("\n-- 7. redis_set nx --")
-- ---------------------------------------------------------------------------
STORE = {}
request_with(nil, BODY)
clear_io()
side_effects({ redis_set = { key = "seen:%{sha256:request.body.urlencode.value:line_id}", value = "first", expire = 1800, nx = true } })
eq(WRITES[1] and WRITES[1].nx, true, "nx = true reaches redis_write")
request_with(nil, BODY)
side_effects({ redis_set = { key = "seen:%{sha256:request.body.urlencode.value:line_id}", value = "second", expire = 1800, nx = true } })
eq(STORE["seen:" .. engine._sha256_hex(LINE)], "first", "with nx the second write leaves the first value")
request_with(nil, BODY)
clear_io()
side_effects({ redis_set = { key = "plain:%{request.body.urlencode.value:line_id}", expire = 60 } })
eq(WRITES[1] and WRITES[1].nx, false, "nx defaults to false")

print("")
print(fails .. " test(s) failed")
os.exit(fails == 0 and 0 or 1)
