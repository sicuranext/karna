-- ka-unittest/redis_counter_ttl.lua
--
-- Guards the fixed-window Redis counter behind `redis_incr_key` — and behind
-- the native `rate_limit` rule action, which calls the same helper — against a
-- race that left a counter with no expiry at all.
--
-- The old shape was three commands:
--
--     exists = GET key          -- was the key there?
--     v      = INCR key
--     if exists == nil then EXPIRE key window end
--
-- If the key expired BETWEEN the GET and the INCR, the INCR recreated it while
-- `exists` still held the old value, the EXPIRE branch was skipped, and the
-- counter lived on with `TTL -1`. It never reset: it climbed past the limit and
-- stayed there. The shorter the window the likelier the race — a 10-second
-- counter reproduces it quickly. For `rate_limit` that is an availability bug,
-- not a metrics one: every request matching the rule gets the terminal 429
-- forever, until someone deletes the key by hand.
--
-- The fix folds INCR and the conditional EXPIRE into one server-side script,
-- so nothing can interleave and it costs one round trip. The window is armed
-- when the INCR's own return value is 1 (the only signal that means "this call
-- created the key", which is why the GET is gone), and re-armed when TTL comes
-- back negative, so a counter already stuck by the old race recovers on its
-- next hit instead of leaking forever.
--
-- The fixture is a miniature Redis: an in-memory key space with real INCR /
-- TTL / EXPIRE semantics, and an `eval` that ACTUALLY EXECUTES the script
-- ka_utils sends (it is Lua) against that key space. Nothing about the
-- helper's logic is restated here — the test runs the shipped script.
--
-- What is pinned:
--   1. one round trip per increment, and no GET on the wire — the race is
--      gone structurally, not by timing;
--   2. a fresh key ends up with the window TTL armed;
--   3. a second increment on a key a previous call created still ends up with
--      a TTL (and does not reset the window);
--   4. a key whose window elapsed between two calls gets a fresh TTL — the
--      exact shape the old code got wrong, and the old algorithm is replayed
--      against the same key space to show the fixture does catch it;
--   5. a counter already stuck with `TTL -1` repairs itself on the next hit;
--   6. no expiry configured still means no expiry (unchanged);
--   7. the deferred (timer) variant behaves identically;
--   8. a Redis error returns nil — callers fail open — and never throws.
--
-- Fixtures are synthetic.
--
-- Run from repo root:
--   lua    ka-unittest/redis_counter_ttl.lua
--   luajit ka-unittest/redis_counter_ttl.lua

package.path = "./kong/plugins/karna/modules/?.lua;" .. package.path

local fails = 0
local function ok(cond, name, detail)
    if cond then print("  ok  - " .. name)
    else print("  FAIL- " .. name .. (detail and ("  (" .. tostring(detail) .. ")") or "")); fails = fails + 1 end
end
local function eq(got, want, name)
    ok(got == want, name, "got " .. tostring(got) .. ", want " .. tostring(want))
end

-- ---------------------------------------------------------------------------
-- ngx / kong stubs (ka_utils captures kong.request.* at module load)
-- ---------------------------------------------------------------------------
_G.ngx = {
    null = setmetatable({}, { __tostring = function() return "ngx.null" end }),
    re   = { match = function() return nil end },
    var  = setmetatable({}, { __index = function() return nil end }),
    log  = function() end,
}
local ERRLOG = {}
_G.kong = {
    log = {
        err   = function(...) ERRLOG[#ERRLOG + 1] = table.concat({ ... }, " ") end,
        warn  = function() end,
        debug = function() end,
    },
    request = {
        get_header = function() return nil end, get_headers = function() return {} end,
        get_path_with_query = function() return "/" end, get_method = function() return "GET" end,
        get_http_version = function() return 1.1 end,
    },
    service  = { response = { get_headers = function() return {} end, get_status = function() return 200 end } },
    response = { get_status = function() return 200 end },
}

-- ---------------------------------------------------------------------------
-- miniature Redis: a key space with real INCR / TTL / EXPIRE semantics
-- ---------------------------------------------------------------------------
-- store[key] = { value = <number>, expires = <seconds> or nil }
local store, SCRIPT_CALLS, WIRE, LAST_SCRIPT, EVAL_ERROR

local function reset_store()
    store, SCRIPT_CALLS, WIRE, LAST_SCRIPT, EVAL_ERROR = {}, {}, {}, nil, nil
end

-- The command set the counter needs, with Redis' own semantics:
--   INCR   creates the key at 1 when absent; NEVER touches an existing TTL.
--   TTL    -2 when the key does not exist, -1 when it has no expiry.
--   EXPIRE arms the expiry; 0 when the key does not exist.
local function redis_call(cmd, key, arg)
    cmd = tostring(cmd):upper()
    SCRIPT_CALLS[#SCRIPT_CALLS + 1] = cmd
    local slot = store[key]
    if cmd == "INCR" then
        if not slot then slot = { value = 0 }; store[key] = slot end
        slot.value = slot.value + 1
        return slot.value
    elseif cmd == "TTL" then
        if not slot then return -2 end
        return slot.expires or -1
    elseif cmd == "EXPIRE" then
        if not slot then return 0 end
        slot.expires = tonumber(arg)
        return 1
    elseif cmd == "GET" then
        if not slot then return nil end
        return tostring(slot.value)
    end
    error("miniature Redis: unsupported command " .. cmd)
end

-- Run the script ka_utils sends, for real, against the key space above.
local function run_script(script, nkeys, ...)
    local packed = { ... }
    local KEYS, ARGV = {}, {}
    for i = 1, nkeys do KEYS[i] = packed[i] end
    for i = nkeys + 1, #packed do ARGV[i - nkeys] = packed[i] end
    local env = {
        KEYS = KEYS, ARGV = ARGV,
        tonumber = tonumber, tostring = tostring, type = type,
        redis = { call = redis_call },
    }
    local fn, err = load(script, "incr-expire", "t", env)
    if not fn then return nil, "script compile error: " .. tostring(err) end
    -- LuaJIT honours load()'s env argument, but be explicit where setfenv exists
    if _G.setfenv then pcall(_G.setfenv, fn, env) end
    local called_ok, res = pcall(fn)
    if not called_ok then return nil, "script runtime error: " .. tostring(res) end
    return res
end

package.preload["resty.redis"] = function()
    local mod = {}
    function mod:new()
        local red = {}
        function red:set_timeouts(...) WIRE[#WIRE + 1] = "set_timeouts" end
        function red:connect(h, p)     WIRE[#WIRE + 1] = "connect"; return true end
        function red:auth(pw)          WIRE[#WIRE + 1] = "auth"; return true end
        -- resty.redis hands back ngx.null for a missing key, not nil
        function red:get(k)
            WIRE[#WIRE + 1] = "get"
            local v = redis_call("GET", k)
            if v == nil then return ngx.null end
            return v
        end
        function red:incr(k)           WIRE[#WIRE + 1] = "incr"; return redis_call("INCR", k) end
        function red:expire(k, t)      WIRE[#WIRE + 1] = "expire"; return redis_call("EXPIRE", k, t) end
        function red:ttl(k)            WIRE[#WIRE + 1] = "ttl"; return redis_call("TTL", k) end
        function red:eval(script, nkeys, ...)
            WIRE[#WIRE + 1] = "eval"
            LAST_SCRIPT = script
            if EVAL_ERROR then return nil, EVAL_ERROR end
            return run_script(script, nkeys, ...)
        end
        return red
    end
    return mod
end

-- KARNA_UNIT_UTILS=<path> loads that file as ka_utils instead of the working
-- tree's, for an A/B of this test against a previous revision:
--   git show <rev>:kong/plugins/karna/modules/ka_utils.lua > /tmp/old_utils.lua
local utils_override = os.getenv("KARNA_UNIT_UTILS")
if utils_override == "" then utils_override = nil end
local utils = dofile(utils_override or "./kong/plugins/karna/modules/ka_utils.lua")
utils.redis_host, utils.redis_port, utils.redis_password = "127.0.0.1", 6379, nil

local function ttl_of(key)
    local slot = store[key]
    if not slot then return -2 end
    return slot.expires or -1
end
local function value_of(key)
    local slot = store[key]
    return slot and slot.value or nil
end
local function count(list, want)
    local n = 0
    for _, v in ipairs(list) do if v == want then n = n + 1 end end
    return n
end

-- ---------------------------------------------------------------------------
-- 1. one round trip, no GET
-- ---------------------------------------------------------------------------
print("\n-- the shape of the conversation with Redis --")

reset_store()
utils:redis_incr_key("karna:rl:900001:203.0.113.7", 60)

eq(count(WIRE, "eval"), 1, "one eval per increment")
eq(count(WIRE, "get"), 0, "no GET on the wire — the racy read is gone")
eq(count(WIRE, "incr"), 0, "no separate INCR round trip")
eq(count(WIRE, "expire"), 0, "no separate EXPIRE round trip")
ok(LAST_SCRIPT and not LAST_SCRIPT:upper():find("GET", 1, true),
   "the script itself never issues a GET")
eq(table.concat(SCRIPT_CALLS, ","), "INCR,EXPIRE",
   "a fresh key: INCR then EXPIRE, nothing else")

-- ---------------------------------------------------------------------------
-- 2 & 3. a fresh key, then a second increment
-- ---------------------------------------------------------------------------
print("\n-- the counter and its window --")

reset_store()
local KEY = "karna:rl:900001:203.0.113.7"

eq(utils:redis_incr_key(KEY, 60), 1, "first increment returns 1")
eq(ttl_of(KEY), 60, "the window is armed on the call that created the key")

SCRIPT_CALLS = {}
eq(utils:redis_incr_key(KEY, 60), 2, "second increment returns 2")
eq(ttl_of(KEY), 60, "a key created by a PREVIOUS call still carries a TTL")
eq(table.concat(SCRIPT_CALLS, ","), "INCR,TTL",
   "the second increment checks the TTL and leaves the armed window alone")

-- the window is not pushed forward on every hit: fixed window, not sliding
store[KEY].expires = 12
utils:redis_incr_key(KEY, 60)
eq(ttl_of(KEY), 12, "an armed window is NOT reset by a later increment")

-- ---------------------------------------------------------------------------
-- 4. the window elapses between two calls
-- ---------------------------------------------------------------------------
print("\n-- the window elapses between two calls (the race) --")

reset_store()
utils:redis_incr_key(KEY, 10)
eq(value_of(KEY), 1, "counter open at 1")
store[KEY] = nil                       -- the 10s window elapses; Redis drops the key
SCRIPT_CALLS = {}
eq(utils:redis_incr_key(KEY, 10), 1, "the next hit opens a fresh window at 1")
eq(ttl_of(KEY), 10, "the recreated key gets a TTL")
eq(table.concat(SCRIPT_CALLS, ","), "INCR,EXPIRE",
   "the increment that recreated the key armed the window")

-- The same fixture, driven through the OLD algorithm, to show it is sharp
-- enough to catch the regression: the key expires between the GET and the
-- INCR, so `exists` is stale and the EXPIRE never happens.
reset_store()
local function old_incr(key, expire_time, expire_between)
    local exists = redis_call("GET", key)          -- key present → not nil
    if expire_between then store[key] = nil end    -- ... and now it expires
    local v = redis_call("INCR", key)
    if exists == nil and expire_time then redis_call("EXPIRE", key, expire_time) end
    return v
end
store[KEY] = { value = 5, expires = 10 }
old_incr(KEY, 10, true)
eq(ttl_of(KEY), -1,
   "the OLD algorithm leaves the recreated key with TTL -1 (the bug, reproduced)")
reset_store()
store[KEY] = { value = 5, expires = 10 }
utils:redis_incr_key(KEY, 10)
ok(ttl_of(KEY) > 0, "the shipped helper cannot reach that state — there is no `between`")

-- ---------------------------------------------------------------------------
-- 5. a counter already stuck with no expiry repairs itself
-- ---------------------------------------------------------------------------
print("\n-- self-repair of a counter stuck by the old bug --")

reset_store()
store[KEY] = { value = 6900, expires = nil }       -- what the deployment found
eq(ttl_of(KEY), -1, "precondition: the stuck counter has no expiry")
SCRIPT_CALLS = {}
eq(utils:redis_incr_key(KEY, 10), 6901, "the stuck counter still increments")
eq(ttl_of(KEY), 10, "and the window is re-armed, so it drains on its own")
eq(table.concat(SCRIPT_CALLS, ","), "INCR,TTL,EXPIRE",
   "the repair is the TTL<0 branch, not the created-it branch")

-- ---------------------------------------------------------------------------
-- 6. no expiry configured
-- ---------------------------------------------------------------------------
print("\n-- no window configured --")

reset_store()
SCRIPT_CALLS = {}
eq(utils:redis_incr_key(KEY, nil), 1, "increments with no expire argument")
eq(ttl_of(KEY), -1, "and arms no expiry, as before")
eq(count(SCRIPT_CALLS, "EXPIRE"), 0, "no EXPIRE is issued when no window is configured")

reset_store()
SCRIPT_CALLS = {}
utils:redis_incr_key(KEY, 0)
eq(ttl_of(KEY), -1, "an expire of 0 is treated as no window")
eq(count(SCRIPT_CALLS, "EXPIRE"), 0, "and issues no EXPIRE")

-- ---------------------------------------------------------------------------
-- 7. the deferred (timer) variant
-- ---------------------------------------------------------------------------
print("\n-- redis_incr_key_async (the header_filter / body_filter path) --")

local conf = { redis_host = "127.0.0.1", redis_port = 6379, redis_password = nil }

reset_store()
utils.redis_incr_key_async(false, utils, conf, KEY, 60)
eq(value_of(KEY), 1, "the async variant increments")
eq(ttl_of(KEY), 60, "and arms the window")
eq(count(WIRE, "get"), 0, "the async variant issues no GET either")
eq(count(WIRE, "eval"), 1, "one round trip")

reset_store()
store[KEY] = { value = 42, expires = nil }
utils.redis_incr_key_async(false, utils, conf, KEY, 30)
eq(value_of(KEY), 43, "the async variant increments an existing counter")
eq(ttl_of(KEY), 30, "and repairs a missing TTL the same way")

reset_store()
utils.redis_incr_key_async(true, utils, conf, KEY, 60)   -- premature: worker shutting down
eq(value_of(KEY), nil, "a premature timer does nothing at all")
eq(count(WIRE, "eval"), 0, "and opens no connection")

-- ---------------------------------------------------------------------------
-- 8. Redis errors: fail open, never throw
-- ---------------------------------------------------------------------------
print("\n-- Redis errors --")

reset_store()
ERRLOG = {}
EVAL_ERROR = "ERR connection reset by peer"
local called_ok, res = pcall(utils.redis_incr_key, utils, KEY, 60)
ok(called_ok, "a failing eval does not throw", res)
eq(res, nil, "and returns nil, so rate_limit fails open")
ok(#ERRLOG > 0, "the failure is logged")

reset_store()
ERRLOG = {}
EVAL_ERROR = "ERR connection reset by peer"
local async_ok, async_err = pcall(utils.redis_incr_key_async, false, utils, conf, KEY, 60)
ok(async_ok, "a failing eval in the timer does not throw", async_err)

print(string.format("\n%d test(s) failed", fails))
os.exit(fails == 0 and 0 or 1)
