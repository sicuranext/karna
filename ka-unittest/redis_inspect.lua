-- ka-unittest/redis_inspect.lua
--
-- Guards ka_utils:redis_inspect_read — the read-only Redis command wrapper that
-- backs the `redis.*` inspection variables and the redis_sismember/redis_hexists
-- operators. The deny-by-default command whitelist is the security boundary
-- (a rule must never be able to mutate Redis or run an admin/scan command), so
-- it gets a deterministic regression guard here. Also covers connect/auth/select,
-- keepalive-on-success vs close-on-error, and ngx.null (absent) handling.
--
-- Run from repo root:
--   lua    ka-unittest/redis_inspect.lua
--   luajit ka-unittest/redis_inspect.lua

package.path = "./kong/plugins/karna/modules/?.lua;" .. package.path
local function map_kpk(short, long)
    package.preload[long] = function()
        return dofile("./kong/plugins/karna/modules/" .. short .. ".lua")
    end
end

-- ngx / kong stubs (ka_utils captures kong.request.* etc. at module load)
_G.ngx = {
    null = setmetatable({}, { __tostring = function() return "ngx.null" end }),
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

-- Fake resty.redis. SCENARIO controls behaviour per test; LOG records calls.
local LOG, SCENARIO = {}, {}
local function reset(s) LOG, SCENARIO = {}, (s or {}) end
local function logged(name)
    for _, c in ipairs(LOG) do if c[1] == name then return c end end
    return nil
end
local fake_redis = {
    new = function(_)
        local red = {}
        function red:set_timeouts(a, b, c) LOG[#LOG + 1] = { "set_timeouts", a, b, c } end
        function red:connect(h, p)
            LOG[#LOG + 1] = { "connect", h, p }
            if SCENARIO.connect_ok == false then return nil, "connection refused" end
            return 1
        end
        function red:auth(pw)
            LOG[#LOG + 1] = { "auth", pw }
            if SCENARIO.auth_ok == false then return nil, "auth failed" end
            return 1
        end
        function red:select(db)
            LOG[#LOG + 1] = { "select", db }
            if SCENARIO.select_ok == false then return nil, "select failed" end
            return 1
        end
        function red:set_keepalive(i, p) LOG[#LOG + 1] = { "set_keepalive", i, p }; return 1 end
        function red:close() LOG[#LOG + 1] = { "close" }; return 1 end
        local function cmd(name)
            return function(_, ...)
                LOG[#LOG + 1] = { name, ... }
                if SCENARIO.err then return nil, SCENARIO.err end
                return SCENARIO.result
            end
        end
        red.get = cmd("get"); red.exists = cmd("exists")
        red.sismember = cmd("sismember"); red.hexists = cmd("hexists")
        red.ttl = cmd("ttl"); red.scard = cmd("scard")
        red.set = cmd("set"); red.sadd = cmd("sadd"); red.srem = cmd("srem")
        red.del = cmd("del"); red.expire = cmd("expire")
        return red
    end,
}
package.preload["resty.redis"] = function() return fake_redis end

map_kpk("ka_utils", "kong.plugins.karna.ka_utils")
local utils = require "kong.plugins.karna.ka_utils"

local failures = 0
local function check(name, cond, detail)
    if cond then print("  ok   - " .. name)
    else failures = failures + 1; print("  FAIL - " .. name .. (detail and ("  (" .. detail .. ")") or "")) end
end

local CONF = { host = "127.0.0.1", port = 6379 }

print("redis_inspect_read:")

-- 1. deny-by-default whitelist: write / admin / scan commands are rejected
--    BEFORE any connection is opened.
for _, bad in ipairs({ "set", "del", "sadd", "srem", "expire", "keys", "scan", "eval", "flushdb", "config" }) do
    reset({})
    local v, e = utils:redis_inspect_read(CONF, bad, "k", "x")
    check("rejects write/admin command: " .. bad, v == nil and e ~= nil and e:find("not allowed", 1, true) ~= nil)
    check("  ...and never connects for " .. bad, logged("connect") == nil)
end

-- 2. EXISTS → 1 / 0
reset({ result = 1 })
local v = utils:redis_inspect_read(CONF, "exists", "ban:1.2.3.4")
check("exists present returns 1", v == 1)
check("exists pooled the connection (keepalive, not close)", logged("set_keepalive") ~= nil and logged("close") == nil)
reset({ result = 0 })
check("exists absent returns 0", utils:redis_inspect_read(CONF, "exists", "ban:1.2.3.4") == 0)

-- 3. GET value / absent(ngx.null)
reset({ result = "blocked" })
check("get returns the stored value", utils:redis_inspect_read(CONF, "get", "flag:u1") == "blocked")
reset({ result = ngx.null })
local gv, ge = utils:redis_inspect_read(CONF, "get", "missing")
check("get on absent key returns ngx.null (not an error)", gv == ngx.null and ge == nil)

-- 4. SISMEMBER / HEXISTS pass key + needle through correctly
reset({ result = 1 })
check("sismember returns 1", utils:redis_inspect_read(CONF, "sismember", "revoked", "tok") == 1)
local sc = logged("sismember")
check("sismember got (set, member)", sc and sc[2] == "revoked" and sc[3] == "tok")
reset({ result = 1 })
check("hexists returns 1", utils:redis_inspect_read(CONF, "hexists", "acl", "consumer-9") == 1)

-- 5. connect failure → nil + error
reset({ connect_ok = false })
local cv, ce = utils:redis_inspect_read(CONF, "get", "k")
check("connect failure → nil + error", cv == nil and ce ~= nil and ce:find("connect", 1, true) ~= nil)

-- 6. command error (e.g. WRONGTYPE) → close the connection, do NOT pool it
reset({ err = "WRONGTYPE Operation against a key holding the wrong kind of value" })
local ev, ee = utils:redis_inspect_read(CONF, "get", "k")
check("command error → nil + error", ev == nil and ee ~= nil)
check("command error closes (does not keepalive a broken conn)", logged("close") ~= nil and logged("set_keepalive") == nil)

-- 7. auth + select issued only when configured
reset({ result = 1 })
utils:redis_inspect_read({ host = "h", port = 1, password = "secret", database = 3 }, "exists", "k")
local auth, sel = logged("auth"), logged("select")
check("auth issued when password set", auth ~= nil and auth[2] == "secret")
check("select issued when database > 0", sel ~= nil and sel[2] == 3)
reset({ result = 1 })
utils:redis_inspect_read({ host = "h", port = 1 }, "exists", "k")
check("no auth/select when not configured", logged("auth") == nil and logged("select") == nil)

-- 8. keepalive uses the configured pool/idle
reset({ result = 1 })
utils:redis_inspect_read({ host = "h", port = 1, keepalive_idle_ms = 5000, keepalive_pool_size = 10 }, "exists", "k")
local ka = logged("set_keepalive")
check("keepalive uses configured idle/pool", ka and ka[2] == 5000 and ka[3] == 10)

print("")
print("redis_write (auto-ban side-effect actions):")

-- write-command whitelist: read/admin commands are NOT writable here
for _, bad in ipairs({ "get", "exists", "keys", "eval", "flushdb", "sismember" }) do
    reset({ result = "OK" })
    local r = utils:redis_write(CONF, bad, "k", "v")
    check("redis_write rejects non-write command: " .. bad, r == nil and logged("connect") == nil)
end

-- SET with TTL → SET key value EX ttl
reset({ result = "OK" })
utils:redis_write(CONF, "set", "ban:1.2.3.4", "1", 600)
local s = logged("set")
check("set with ttl issues SET key value EX ttl", s and s[2] == "ban:1.2.3.4" and s[3] == "1" and s[4] == "EX" and s[5] == 600)
check("set pooled the connection", logged("set_keepalive") ~= nil)

-- SET without TTL → no EX
reset({ result = "OK" })
utils:redis_write(CONF, "set", "k", "v")
local s2 = logged("set")
check("set without ttl issues plain SET", s2 and s2[2] == "k" and s2[3] == "v" and s2[4] == nil)

-- SADD with TTL → SADD then EXPIRE on the set key
reset({ result = 1 })
utils:redis_write(CONF, "sadd", "revoked", "tok", 300)
local sa, ex = logged("sadd"), logged("expire")
check("sadd issues SADD set member", sa and sa[2] == "revoked" and sa[3] == "tok")
check("sadd with ttl also EXPIREs the key", ex and ex[2] == "revoked" and ex[3] == 300)

-- DEL
reset({ result = 1 })
utils:redis_write(CONF, "del", "ban:1.2.3.4")
local d = logged("del")
check("del issues DEL key", d and d[2] == "ban:1.2.3.4")

-- connect failure on a write → nil, fail-soft
reset({ connect_ok = false })
check("write connect failure → nil (fail-soft)", utils:redis_write(CONF, "set", "k", "v") == nil)

print("")
if failures == 0 then print("ALL PASS"); os.exit(0)
else print(failures .. " FAILURE(S)"); os.exit(1) end
