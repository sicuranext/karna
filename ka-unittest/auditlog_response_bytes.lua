-- ka-unittest/auditlog_response_bytes.lua
--
-- Guards the response.bytes field of the audit log: the number of bytes
-- nginx actually wrote to the client for this response (status line +
-- headers + body, on-the-wire size), read from $bytes_sent in the log phase.
--
-- Load-bearing properties pinned here:
--   1. v2 publishes it as response.bytes, v1 as transaction.response.bytes,
--      both as a NUMBER (not the string ngx.var hands back), so a collector
--      can sum / range-query it without a cast;
--   2. the field is always present: a missing or unparsable $bytes_sent
--      (never happens in nginx, does happen in stubs) yields 0, not nil, so
--      the document shape does not flicker between requests;
--   3. no 32-bit truncation on large responses;
--   4. the two response blocks gained exactly this one key and nothing else.
--
-- Loads the REAL ka_utils.lua behind ngx/kong stubs (same approach as
-- external_log_entries_v1.lua), so it cannot drift from the source.
--
-- Run from repo root:
--   lua    ka-unittest/auditlog_response_bytes.lua
--   luajit ka-unittest/auditlog_response_bytes.lua

local fails = 0
local function ok(cond, name)
    if cond then print("  ok  - " .. name)
    else print("  FAIL- " .. name); fails = fails + 1 end
end

local function keyset(t)
    local ks = {}
    for k in pairs(t) do ks[#ks + 1] = tostring(k) end
    table.sort(ks)
    return table.concat(ks, ",")
end

-- ---------------------------------------------------------------------------
-- stubs: cjson (only empty_array is used on these paths) + the version module
-- ---------------------------------------------------------------------------
-- empty_array is a lightuserdata sentinel in the real lua-cjson; a coroutine
-- is the closest non-table stand-in (see external_log_entries_v1.lua).
local CJSON = { empty_array = coroutine.create(function() end) }
package.preload["cjson"] = function() return CJSON end
package.preload["kong.plugins.karna.version"] = function()
    return { version = "0.0.0-test", commit = "deadbee", commit_short = "deadbee", built_at = "test" }
end

-- ---------------------------------------------------------------------------
-- ngx / kong stubs — the minimum get_auditlog + get_auditlog_v2 touch
-- ---------------------------------------------------------------------------
_G.ngx = {
    re = { match = function() return nil end },
    now = function() return 1700000000.5 end,
    time = function() return 1700000000 end,
    var = {
        request_id       = "req-0001",
        remote_addr      = "203.0.113.7",
        remote_port      = "51234",
        server_addr      = "10.0.0.1",
        server_port      = "8000",
        server_id        = "srv-1",
        request_time     = "0.030",
        upstream_response_time = "0.020",
        bytes_sent       = "1536",
    },
    log = function() end,
    worker = { id = function() return 0 end },
}
_G.kong = {
    log = { debug = function() end, warn = function() end, err = function() end, notice = function() end },
    ctx = { shared = {}, plugin = {} },
    router = {
        get_service = function() return { id = "svc-1", name = "acme_www.example.com" } end,
        get_route   = function() return { id = "route-1" } end,
    },
    request = {
        get_header             = function() return nil end,
        get_headers            = function() return { host = "www.example.com", ["user-agent"] = "curl/8" } end,
        get_path_with_query    = function() return "/docs?page=1" end,
        get_method             = function() return "GET" end,
        get_http_version       = function() return 1.1 end,
    },
    response = {
        get_status  = function() return 200 end,
        get_headers = function() return { ["content-type"] = "text/html", ["content-length"] = "1200" } end,
    },
    service = {
        response = {
            get_status  = function() return 200 end,
            get_headers = function() return { ["content-type"] = "text/html" } end,
        },
    },
}

local utils = dofile("./kong/plugins/karna/modules/ka_utils.lua")

local PLUGIN_CONF = { engine_blocking_mode = true, paranoia_level = 1 }

-- a rule match for the v1 path: the status override must not disturb bytes
local RULE  = { id = "900001", message = "test rule", tags = { "karna-test" }, response_status_override = 403 }
local PARTS = { { matched_on = "request.arg.value:q", matched_value = "x" } }

-- ============================================================
print("- v2: response.bytes from $bytes_sent")
-- ============================================================
local v2 = utils:get_auditlog_v2({}, PLUGIN_CONF)
ok(v2.response.bytes == 1536, "value is the nginx counter")
ok(type(v2.response.bytes) == "number", "published as a number, not the ngx.var string")
ok(keyset(v2.response) == "bytes,headers,latencies,latency_ms,status",
   "response block gained exactly one key (bytes)")

-- ============================================================
print("")
print("- v1: transaction.response.bytes from $bytes_sent")
-- ============================================================
local v1 = utils:get_auditlog(nil, nil)
ok(v1.transaction.response.bytes == 1536, "value is the nginx counter")
ok(type(v1.transaction.response.bytes) == "number", "published as a number")
ok(keyset(v1.transaction.response) == "bytes,headers,http_code",
   "response block gained exactly one key (bytes)")

v1 = utils:get_auditlog(RULE, PARTS)
ok(v1.transaction.response.http_code == 403, "status override still applied on a match")
ok(v1.transaction.response.bytes == 1536, "bytes untouched by the status override")

-- ============================================================
print("")
print("- always present: missing / garbage counter → 0, not nil")
-- ============================================================
ngx.var.bytes_sent = nil
v2 = utils:get_auditlog_v2({}, PLUGIN_CONF)
v1 = utils:get_auditlog(nil, nil)
ok(v2.response.bytes == 0, "v2: absent counter → 0")
ok(v1.transaction.response.bytes == 0, "v1: absent counter → 0")

ngx.var.bytes_sent = "not-a-number"
v2 = utils:get_auditlog_v2({}, PLUGIN_CONF)
v1 = utils:get_auditlog(nil, nil)
ok(v2.response.bytes == 0, "v2: unparsable counter → 0")
ok(v1.transaction.response.bytes == 0, "v1: unparsable counter → 0")

-- ============================================================
print("")
print("- no 32-bit truncation")
-- ============================================================
ngx.var.bytes_sent = "4294967296"
v2 = utils:get_auditlog_v2({}, PLUGIN_CONF)
v1 = utils:get_auditlog(nil, nil)
ok(v2.response.bytes == 4294967296, "v2: 4 GiB response keeps its size")
ok(v1.transaction.response.bytes == 4294967296, "v1: 4 GiB response keeps its size")

-- ============================================================
print("")
print("- a blocked request is counted like any other response")
-- ============================================================
-- Karna's own 403 page is written by nginx too, so $bytes_sent is simply the
-- size of the block page. Nothing special-cased: same read, same field.
ngx.var.bytes_sent = "312"
kong.response.get_status = function() return 403 end
v2 = utils:get_auditlog_v2({}, PLUGIN_CONF)
ok(v2.response.status == 403 and v2.response.bytes == 312, "v2: block page size reported")

print(string.format("\n%d test(s) failed", fails))
os.exit(fails == 0 and 0 or 1)
