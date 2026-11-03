-- ka-unittest/request_body_limit.lua
--
-- engine:check_request_body_limit, the request_body_limit gate (413).
--
--   1. a body at or under the limit passes and is not recorded;
--   2. over the limit: recorded as request_body_limit, true in detection mode
--      (the handler skips the rules), 413 + x-karna-rule-id in blocking mode;
--   3. a request_body_limit_overrides entry replaces the limit and is named
--      in the message;
--   4. a chunked body (no Content-Length) is measured like any other;
--   5. a body nginx kept in a temp file is measured from the file size and
--      not read into Lua;
--   6. application/octet-stream over the limit passes uninspected (every body
--      getter resolves empty) unless it starts like JSON, or with nothing but
--      whitespace in the sniffed prefix: then it is refused;
--   7. under body_access_off the body is not measured at all.
--
-- Multipart (only non-file parts count) needs the real ka_multipart parser,
-- which the harness stubs: covered by the DEV integration run instead.
--
-- Run from the repo root: lua ka-unittest/request_body_limit.lua

local H = dofile("./ka-unittest/_engine_harness.lua")
local engine = H.engine

local pass, fail = 0, 0
local function ok(cond, msg, extra)
    if cond then
        pass = pass + 1
        print("  ok   " .. msg)
    else
        fail = fail + 1
        print("  FAIL " .. msg .. (extra ~= nil and ("  [" .. tostring(extra) .. "]") or ""))
    end
end

local exits = {}
kong.response.exit = function(status, body, headers)
    exits[#exits + 1] = { status = status, body = body, headers = headers or {} }
    return status
end

local function request(ct, body, opts)
    opts = opts or {}
    H.request.method    = "POST"
    H.request.path      = opts.path or "/api/x"
    H.request.raw_path  = H.request.path
    H.request.raw_query = ""
    H.request.headers   = { ["Content-Type"] = ct }
    if opts.chunked then
        H.request.headers["Transfer-Encoding"] = "chunked"
    else
        H.request.headers["Content-Length"] = tostring(opts.length or #body)
    end
    H.request.body      = body
    H.request.body_file = nil
end

local function fresh(off)
    local rc = H.reset()
    kong.ctx.plugin.ka_matched_rules = {}
    rc.body_access_off = off == true
    exits = {}
end

local function recorded()
    local m = kong.ctx.plugin.ka_matched_rules[1]
    return m and m.rule.id, m and m.rule.message
end

local LIMIT = 1000
local function conf(extra)
    local c = {
        engine_blocking_mode = false,
        request_body_limit = LIMIT,
        try_bas64decode_if_possible = false,
    }
    for k, v in pairs(extra or {}) do c[k] = v end
    return c
end

local function json_of(n)
    -- {"a":"xxx…"} of exactly n bytes
    return '{"a":"' .. string.rep("x", n - 8) .. '"}'
end

print("1. at or under the limit")
request("application/json", json_of(LIMIT))
fresh()
ok(engine:check_request_body_limit(conf()) == false, "body of exactly the limit passes")
ok(recorded() == nil, "nothing recorded")

print("2. over the limit")
request("application/json", json_of(LIMIT + 1))
fresh()
ok(engine:check_request_body_limit(conf()) == true, "detection mode: true (rules skipped)")
local id, msg = recorded()
ok(id == "request_body_limit", "recorded as request_body_limit", id)
ok(msg and msg:find("1001 > 1000", 1, true), "message carries size and limit", msg)
ok(#exits == 0, "no response in detection mode")

fresh()
engine:check_request_body_limit(conf({ engine_blocking_mode = true }))
ok(exits[1] and exits[1].status == 413, "blocking mode: 413", exits[1] and exits[1].status)
ok(exits[1] and exits[1].headers["x-karna-rule-id"] == "request_body_limit",
   "x-karna-rule-id: request_body_limit")

print("3. per-path override")
fresh()
local override = { path_rx = "^/big$", limit = 5000 }
ok(engine:check_request_body_limit(conf(), override) == false, "override raises the limit: passes")
local small = { path_rx = "^/tiny$", limit = 10 }
request("application/json", json_of(100))
fresh()
ok(engine:check_request_body_limit(conf(), small) == true, "override lowers the limit: refused")
id, msg = recorded()
ok(msg and msg:find("override ^/tiny$", 1, true), "message names the override", msg)

print("4. chunked body, no Content-Length")
request("application/json", json_of(LIMIT * 2), { chunked = true })
fresh()
ok(engine:check_request_body_limit(conf()) == true, "chunked body over the limit is refused")

print("5. body kept in a temp file")
do
    local path = os.tmpname()
    local fh = assert(io.open(path, "wb"))
    fh:write(json_of(LIMIT * 3))
    fh:close()
    request("application/json", "", { length = LIMIT * 3 })
    H.request.body      = nil
    H.request.body_file = path
    fresh()
    ok(engine:check_request_body_limit(conf()) == true, "measured from the file size")
    ok(kong.ctx.plugin.ka_raw_body == nil, "body not read into Lua")
    os.remove(path)
end

print("6. application/octet-stream")
local binary = "7z\188\175\39\28" .. string.rep("\1\2\3\250", 600)
request("application/octet-stream", binary)
fresh()
ok(engine:check_request_body_limit(conf()) == false, "binary over the limit passes")
ok(kong.ctx.plugin.ka_body_uninspected == true, "marked uninspected")
ok(recorded() == nil, "nothing recorded")
local scal = engine.__get_values_request_body_scalars()
ok(scal["request.body"] == nil, "request.body resolves empty")
ok(next(engine.__get_values_request_body(false)) == nil, "structured body getter resolves empty")

request("application/octet-stream", binary:sub(1, 500))
fresh()
ok(engine:check_request_body_limit(conf()) == false and kong.ctx.plugin.ka_body_uninspected == nil,
   "binary under the limit: inspected as before")

request("application/octet-stream", json_of(LIMIT * 2))
fresh()
ok(engine:check_request_body_limit(conf()) == true, "JSON sent as octet-stream over the limit: refused")

request("application/octet-stream; charset=binary", "  \n [" .. string.rep("1,", LIMIT) .. "1]")
fresh()
ok(engine:check_request_body_limit(conf()) == true, "JSON array after whitespace, CT with parameters: refused")

request("application/octet-stream", string.rep(" ", 5000) .. json_of(LIMIT))
fresh()
ok(engine:check_request_body_limit(conf()) == true, "whitespace-only sniffed prefix: refused")

request("text/plain", string.rep("a", LIMIT * 2))
fresh()
ok(engine:check_request_body_limit(conf()) == true, "other non-structured types are refused")

print("7. body_access_off")
request("application/json", json_of(LIMIT * 2))
fresh(true)
ok(engine:check_request_body_limit(conf()) == false, "not measured under body_access_off")
ok(kong.ctx.plugin.ka_raw_body == nil, "body never read")

print(string.format("\nrequest_body_limit: %d passed, %d failed", pass, fail))
os.exit(fail == 0 and 0 or 1)
