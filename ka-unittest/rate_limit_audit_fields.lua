-- ka-unittest/rate_limit_audit_fields.lua
--
-- The `rate_limit` action's counter state in the audit log.
--
-- Up to 1.5.8 handler.lua set four fields on the match entry — rate_limit_count,
-- _limit, _window, _key — and NOTHING read them back. The v2 `matches[]` entry
-- was a fixed literal of five keys, so none of the four ever reached the
-- document, although the README had documented the names for several releases.
-- A throttled request was therefore unanswerable from the log: you could see
-- that a rule matched, not what the counter stood at or which key it used.
--
-- This pins the two builders and drives the REAL get_auditlog_v2 /
-- get_auditlog, so it fails if the wiring is dropped again rather than only if
-- the helpers change.
--
-- v1 is the ModSecurity-shaped document and gains no new keys (same rule as
-- build_v1_external_messages, which folds a sibling plugin's `source` into
-- `details.data`), so the same state is appended to `details.data` as one line
-- of text. A match that carried no rate_limit action must be untouched in both
-- formats.
--
-- Fixtures are synthetic.
--
-- Run from repo root:
--   lua    ka-unittest/rate_limit_audit_fields.lua
--   luajit ka-unittest/rate_limit_audit_fields.lua

package.path = "./kong/plugins/karna/modules/?.lua;" .. package.path
package.preload["inspect"] = function() return function() return "" end end

local fails = 0
local function ok(cond, name, detail)
    if cond then print("  ok  - " .. name)
    else print("  FAIL- " .. name .. (detail and ("  (" .. tostring(detail) .. ")") or "")); fails = fails + 1 end
end
local function eq(got, want, name)
    ok(got == want, name, "got " .. tostring(got) .. ", want " .. tostring(want))
end

-- ---------------------------------------------------------------------------
-- ngx / kong stubs — the minimum get_auditlog + get_auditlog_v2 touch
-- ---------------------------------------------------------------------------
local CJSON = { empty_array = coroutine.create(function() end) }
package.preload["cjson"] = function() return CJSON end
package.preload["kong.plugins.karna.version"] = function()
    return { version = "0.0.0-test", commit = "deadbee", commit_short = "deadbee", built_at = "test" }
end
_G.ngx = {
    re   = { match = function() return nil end },
    now  = function() return 1700000000.5 end,
    time = function() return 1700000000 end,
    var  = { request_id = "req-0003", remote_addr = "203.0.113.7", remote_port = "51234",
             server_addr = "10.0.0.1", server_port = "8000", server_id = "srv-1",
             request_time = "0.030", upstream_response_time = "0.020", bytes_sent = "512" },
    log  = function() end,
    worker = { id = function() return 0 end },
    encode_base64 = function(s) return s end,
}
_G.kong = {
    log = { debug = function() end, warn = function() end, err = function() end, notice = function() end },
    ctx = { shared = {}, plugin = {} },
    router = {
        get_service = function() return { id = "svc-1", name = "acme_api.example.com" } end,
        get_route   = function() return { id = "route-1" } end,
    },
    request = {
        get_header          = function() return nil end,
        get_headers         = function() return { host = "api.example.com" } end,
        get_path_with_query = function() return "/login" end,
        get_method          = function() return "POST" end,
        get_http_version    = function() return 1.1 end,
    },
    response = {
        get_status  = function() return 429 end,
        get_headers = function() return {} end,
    },
    service = { response = { get_status = function() return 429 end, get_headers = function() return {} end } },
}

local utils = dofile("./kong/plugins/karna/modules/ka_utils.lua")

local KEY  = "karna:rl:11111111-2222-3333-4444-555555555555:rl-login:203.0.113.7"
local CONF = { engine_blocking_mode = true, paranoia_level = 1, auditlog_format = "v2" }

print("\n-- audit eligibility --")
eq(utils:is_match_audit_eligible({rule = {log = true}, audit_loggable = false}), false,
   "an admitted rate-limit match is quiet by default")
eq(utils:is_match_audit_eligible({rule = {log = true}, audit_loggable = true}), true,
   "an enforcement event is audit eligible")
eq(utils:is_match_audit_eligible({rule = {log = false}, audit_loggable = true}), false,
   "the rule-level log flag remains the master switch")
eq(utils:is_match_audit_eligible({rule = {log = true}}), true,
   "ordinary matches retain their existing logging behavior")

-- A match entry as handler.lua fills it at dispatch: the rule, the matched
-- parts, and the rate_limit_* bookkeeping alongside them.
local function rl_entry(count)
    return {
        rule = { id = "rl-login", message = "login rate limit 5/10s", tags = { "ratelimit" } },
        part = {},
        rate_limit_count  = count,
        rate_limit_limit  = 5,
        rate_limit_window = 10,
        rate_limit_key    = KEY,
        rate_limited      = count > 5,
        blocked           = count > 5,
    }
end

local function plain_entry()
    return {
        rule = { id = "942100", message = "SQLi", tags = { "attack-sqli" } },
        part = {},
        blocked = true,
    }
end

local function active_ban_entry()
    return {
        rule = { id = "rl-login", message = "login temporarily blocked", tags = { "ratelimit" } },
        part = {},
        blocked = true,
        rate_limited = true,
        rate_limit_ban_key = "karna:ban:scope:service:rl-login:identity",
        rate_limit_ban_created = false,
        rate_limit_ban_active = true,
        rate_limit_ban_ttl = 45,
    }
end

-- ---------------------------------------------------------------------------
-- 1. build_rate_limit_fields
-- ---------------------------------------------------------------------------
print("\n-- build_rate_limit_fields --")

eq(utils:build_rate_limit_fields(nil), nil, "nil match → no fields")
eq(utils:build_rate_limit_fields("nope"), nil, "a non-table → no fields")
eq(utils:build_rate_limit_fields(plain_entry()), nil,
   "a match with no rate_limit action contributes no fields at all")

local f = utils:build_rate_limit_fields(rl_entry(6))
eq(f.rate_limit_count,  6,   "the post-increment counter")
eq(f.rate_limit_limit,  5,   "the configured limit")
eq(f.rate_limit_window, 10,  "the window")
eq(f.rate_limit_key,    KEY, "the key, so an operator can find or DEL it")

-- Numbers, not strings: a consumer must be able to compare them without
-- parsing, and the key must be a string even if the macro resolved to a number.
ok(type(f.rate_limit_count) == "number" and type(f.rate_limit_limit) == "number"
   and type(f.rate_limit_window) == "number", "counters are numbers")
ok(type(f.rate_limit_key) == "string", "the key is a string")

local fb = utils:build_rate_limit_fields(active_ban_entry())
eq(fb.rate_limit_key, nil, "an active ban does not invent a counter key")
eq(fb.rate_limit_ban_active, true, "an enforced ban is marked active")
eq(fb.rate_limit_ban_ttl, 45, "an enforced ban carries its remaining TTL")

local partial = { rate_limit_key = KEY }
local fp = utils:build_rate_limit_fields(partial)
eq(fp.rate_limit_count, 0, "a missing count reads 0, never nil")
eq(fp.rate_limit_limit, 0, "so does a missing limit")

-- Redis unreachable: the handler leaves the count nil and the request is not
-- refused. The record must still say which key was consulted.
local unreachable = rl_entry(0)
unreachable.rate_limit_count = nil
eq(utils:build_rate_limit_fields(unreachable).rate_limit_key, KEY,
   "Redis down → still reports the key it tried")

-- ---------------------------------------------------------------------------
-- 2. audit log v2 — the real builder
-- ---------------------------------------------------------------------------
print("\n-- audit log v2 --")

local v2 = utils:get_auditlog_v2({ rl_entry(6) }, CONF)
local m = v2.matches[1]
ok(m ~= nil, "one match recorded")
eq(m.rule_id, "rl-login", "the rule id")
eq(m.rate_limit_count,  6,   "v2 carries the counter")
eq(m.rate_limit_limit,  5,   "v2 carries the limit")
eq(m.rate_limit_window, 10,  "v2 carries the window")
eq(m.rate_limit_key,    KEY, "v2 carries the key")

local mb = utils:get_auditlog_v2({ active_ban_entry() }, CONF).matches[1]
eq(mb.action, "banned", "an enforced ban has a distinct action")
eq(mb.rate_limit_ban_active, true, "v2 carries active-ban state")
eq(mb.rate_limit_ban_ttl, 45, "v2 carries the remaining ban TTL")

-- The regression that started this: the entry used to be a fixed five-key
-- literal, so the fields were dropped on the floor.
local v2_plain = utils:get_auditlog_v2({ plain_entry() }, CONF)
local mp = v2_plain.matches[1]
eq(mp.rate_limit_key, nil, "an ordinary match gains no rate_limit key")
eq(mp.rate_limit_count, nil, "nor a counter")
ok(mp.rule_id and mp.message and mp.tags and mp.action,
   "and keeps the five keys it always had")

-- Mixed request: a CRS match and a rate-limit match in the same record. Only
-- the second carries the extra keys.
local v2_mixed = utils:get_auditlog_v2({ plain_entry(), rl_entry(9) }, CONF)
eq(#v2_mixed.matches, 2, "both matches recorded")
eq(v2_mixed.matches[1].rate_limit_key, nil, "the CRS match stays clean")
eq(v2_mixed.matches[2].rate_limit_count, 9, "the rate-limit match carries its counter")

-- ---------------------------------------------------------------------------
-- 3. audit log v1 — folded into details.data, no new key
-- ---------------------------------------------------------------------------
print("\n-- audit log v1 --")

eq(utils:build_v1_rate_limit_data(plain_entry()), nil,
   "a match with no rate_limit action contributes nothing to the v1 data slot")

local d = utils:build_v1_rate_limit_data(rl_entry(6))
ok(d:find("Rate limit: ", 1, true) == 1, "the v1 line is prefixed", d)
ok(d:find("count=6", 1, true) ~= nil, "v1 says the counter", d)
ok(d:find("limit=5", 1, true) ~= nil, "v1 says the limit", d)
ok(d:find("window=10", 1, true) ~= nil, "v1 says the window", d)
ok(d:find("key=" .. KEY, 1, true) ~= nil, "v1 says the key", d)

local db = utils:build_v1_rate_limit_data(active_ban_entry())
ok(db:find("ban_active=true", 1, true) ~= nil,
   "v1 records enforcement of an already-active ban", db)
ok(db:find("count=", 1, true) == nil,
   "v1 does not invent counter state for active-ban enforcement", db)

local entry = rl_entry(6)
local v1 = utils:get_auditlog(entry.rule, entry.part, entry)
local msg = v1.transaction and v1.transaction.messages and v1.transaction.messages[1]
ok(msg ~= nil, "v1 records one message")
ok(msg and msg.details and msg.details.data
   and msg.details.data:find("Rate limit: count=6", 1, true) ~= nil,
   "the v1 message carries the state in details.data", msg and msg.details and msg.details.data)

local keys = {}
for k in pairs(msg.details) do keys[#keys + 1] = k end
table.sort(keys)
eq(table.concat(keys, ","), "data,ruleId,tags", "v1 details gains no new key")

-- A rule that is not a rate limiter must produce the v1 document it always did.
local pe = plain_entry()
local v1_plain = utils:get_auditlog(pe.rule, pe.part, pe)
local msg_plain = v1_plain.transaction.messages[1]
ok(msg_plain.details.data:find("Rate limit", 1, true) == nil,
   "an ordinary match mentions no rate limit in v1", msg_plain.details.data)

-- Called the old way (no match entry at all) nothing must break: handler.lua
-- still calls get_auditlog(nil, nil) when there is no loggable match.
local okc = pcall(function() return utils:get_auditlog(entry.rule, entry.part) end)
ok(okc, "get_auditlog without the third argument still works")

print(string.format("\n%d test(s) failed", fails))
os.exit(fails == 0 and 0 or 1)
