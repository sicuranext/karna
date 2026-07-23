-- ka-unittest/global_rules.lua
--
-- Guards ka_global_rules — the Redis-distributed global rules pack. The
-- security boundary here is the HMAC verification (a pack with a bad or
-- missing signature must NEVER be applied when a key is configured) plus the
-- version monotonicity check (no replay of older signed packs), so both get
-- deterministic regression coverage. Also covers: redis URL parsing, the
-- deterministic build order (JSON author order first, then SecLang sorted by
-- id), phase splitting, insane-rule dropping, and the poll state machine
-- (unchanged / applied / cleared / keep-last-known-good on errors).
--
-- Run from repo root:
--   lua    ka-unittest/global_rules.lua
--   luajit ka-unittest/global_rules.lua

package.path = "./kong/plugins/karna/modules/?.lua;" .. package.path
local function map_kpk(short, long)
    package.preload[long] = function()
        return dofile("./kong/plugins/karna/modules/" .. short .. ".lua")
    end
end

-- ---------------------------------------------------------------------------
-- ngx / kong stubs
-- ---------------------------------------------------------------------------
local WARNINGS, ERRORS, NOTICES = {}, {}, {}
_G.ngx = {
    null = setmetatable({}, { __tostring = function() return "ngx.null" end }),
    worker = { id = function() return 0 end },
    timer = {
        at = function() return true end,
        every = function() return true end,
    },
    log = function() end,
}
_G.kong = {
    log = {
        debug  = function() end,
        warn   = function(...) WARNINGS[#WARNINGS + 1] = table.concat({...}, "") end,
        err    = function(...) ERRORS[#ERRORS + 1] = table.concat({...}, "") end,
        notice = function(...) NOTICES[#NOTICES + 1] = table.concat({...}, "") end,
    },
}

-- minimal pure-Lua JSON decoder (arrays/objects/strings/numbers/bools/null),
-- enough for the rule fixtures below.
local function json_decode(s)
    local pos = 1
    local function skip() pos = s:find("[^ \t\r\n]", pos) or #s + 1 end
    local decode_value
    local function decode_string()
        pos = pos + 1
        local out = {}
        while true do
            local ch = s:sub(pos, pos)
            if ch == '"' then pos = pos + 1; return table.concat(out) end
            if ch == "\\" then
                local nxt = s:sub(pos + 1, pos + 1)
                local map = { n = "\n", t = "\t", r = "\r", ['"'] = '"', ["\\"] = "\\", ["/"] = "/" }
                out[#out + 1] = map[nxt] or nxt
                pos = pos + 2
            else
                out[#out + 1] = ch
                pos = pos + 1
            end
        end
    end
    local function decode_array()
        pos = pos + 1
        local arr = {}
        skip()
        if s:sub(pos, pos) == "]" then pos = pos + 1; return arr end
        while true do
            arr[#arr + 1] = decode_value()
            skip()
            local ch = s:sub(pos, pos)
            pos = pos + 1
            if ch == "]" then return arr end
            if ch ~= "," then error("bad array") end
            skip()
        end
    end
    local function decode_object()
        pos = pos + 1
        local obj = {}
        skip()
        if s:sub(pos, pos) == "}" then pos = pos + 1; return obj end
        while true do
            skip()
            if s:sub(pos, pos) ~= '"' then error("bad key") end
            local k = decode_string()
            skip()
            if s:sub(pos, pos) ~= ":" then error("bad colon") end
            pos = pos + 1
            skip()
            obj[k] = decode_value()
            skip()
            local ch = s:sub(pos, pos)
            pos = pos + 1
            if ch == "}" then return obj end
            if ch ~= "," then error("bad object") end
        end
    end
    decode_value = function()
        skip()
        local ch = s:sub(pos, pos)
        if ch == "[" then return decode_array() end
        if ch == "{" then return decode_object() end
        if ch == '"' then return decode_string() end
        if s:sub(pos, pos + 3) == "true" then pos = pos + 4; return true end
        if s:sub(pos, pos + 4) == "false" then pos = pos + 5; return false end
        if s:sub(pos, pos + 3) == "null" then pos = pos + 4; return nil end
        local num = s:match("^-?%d+%.?%d*[eE]?[+-]?%d*", pos)
        if num then pos = pos + #num; return tonumber(num) end
        error("bad value at " .. pos)
    end
    local ok, res = pcall(decode_value)
    if not ok then error(res) end
    return res
end

package.preload["cjson"] = function()
    return { decode = json_decode, encode = function() return "" end }
end

-- Fake resty.redis, scenario-driven like ka-unittest/redis_inspect.lua.
local LOG, SCENARIO = {}, {}
local function reset(s) LOG, SCENARIO = {}, (s or {}) end
local function logged(name)
    for _, c in ipairs(LOG) do if c[1] == name then return c end end
    return nil
end
local fake_redis = {
    new = function(_)
        local red = {}
        function red:set_timeouts(...) LOG[#LOG + 1] = { "set_timeouts" } end
        function red:connect(h, p, o)
            LOG[#LOG + 1] = { "connect", h, p, o }
            if SCENARIO.connect_ok == false then return nil, "connection refused" end
            return 1
        end
        function red:auth(a, b) LOG[#LOG + 1] = { "auth", a, b }; return 1 end
        function red:select(db) LOG[#LOG + 1] = { "select", db }; return 1 end
        function red:set_keepalive(...) LOG[#LOG + 1] = { "set_keepalive" }; return 1 end
        function red:close() LOG[#LOG + 1] = { "close" }; return 1 end
        function red:hget(key, field)
            LOG[#LOG + 1] = { "hget", key, field }
            local f = SCENARIO.fields
            if not f or f.version == nil then return _G.ngx.null end
            return f.version
        end
        function red:hgetall(key)
            LOG[#LOG + 1] = { "hgetall", key }
            local f = SCENARIO.fields or {}
            local arr = {}
            for k, v in pairs(f) do arr[#arr + 1] = k; arr[#arr + 1] = v end
            return arr
        end
        return red
    end,
}
package.preload["resty.redis"] = function() return fake_redis end

map_kpk("seclang", "kong.plugins.karna.ka_seclang")
map_kpk("ka_global_rules", "kong.plugins.karna.ka_global_rules")
local gr = require "kong.plugins.karna.ka_global_rules"

-- Deterministic fake crypto: sha256 → "h<payload len>", hmac → "mac.<key>.<msg>".
-- All-lowercase because verify() hex-normalizes the stored sig with :lower();
-- the verify logic under test only needs both sides to be pure functions.
gr._sha256_hex = function(s) return "h" .. tostring(#(s or "")) end
gr._hmac_sha256_hex = function(key, msg)
    return ("mac." .. key .. "." .. msg:gsub("\n", "_")):lower()
end
local function sign(key, fields)
    local msg = tostring(fields.version or "") .. "\n"
        .. gr._sha256_hex(fields.json or "") .. "\n"
        .. gr._sha256_hex(fields.seclang or "")
    return gr._hmac_sha256_hex(key, msg)
end

local failures = 0
local function check(name, cond, detail)
    if cond then print("  ok   - " .. name)
    else failures = failures + 1; print("  FAIL - " .. name .. (detail and ("  (" .. detail .. ")") or "")) end
end

-- ---------------------------------------------------------------------------
print("parse_redis_url:")
-- ---------------------------------------------------------------------------

local u = gr.parse_redis_url("redis://karna-redis:6379/0")
check("host/port/db", u and u.host == "karna-redis" and u.port == 6379 and u.database == 0 and u.ssl == false)

u = gr.parse_redis_url("redis://myhost")
check("defaults: port 6379, db 0", u and u.host == "myhost" and u.port == 6379 and u.database == 0)

u = gr.parse_redis_url("redis://:sekret@myhost:7000/3")
check("password + db", u and u.password == "sekret" and u.port == 7000 and u.database == 3 and u.user == nil)

u = gr.parse_redis_url("redis://alice:s3c@myhost")
check("acl user + password", u and u.user == "alice" and u.password == "s3c")

u = gr.parse_redis_url("redis://:p@ss@myhost:6379")
check("password containing @ (split on last @)", u and u.password == "p@ss" and u.host == "myhost")

u = gr.parse_redis_url("rediss://myhost:6380")
check("rediss:// sets ssl", u and u.ssl == true and u.port == 6380)

local bad, err = gr.parse_redis_url("http://nope")
check("non-redis scheme rejected", bad == nil and err ~= nil)
bad = gr.parse_redis_url("redis://")
check("missing host rejected", bad == nil)

-- ---------------------------------------------------------------------------
print("")
print("verify (HMAC boundary):")
-- ---------------------------------------------------------------------------

local KEY = "unit-test-key"
local fields = { version = "1", json = '[{"id":"g1"}]', seclang = "" }
fields.sig = sign(KEY, fields)
check("valid signature accepted", gr.verify(fields, KEY) == true)

local tampered = { version = fields.version, json = '[{"id":"EVIL"}]', seclang = "", sig = fields.sig }
local ok, why = gr.verify(tampered, KEY)
check("tampered json rejected", ok == nil and why ~= nil, tostring(why))

local nosig = { version = "1", json = "[]", seclang = "" }
ok, why = gr.verify(nosig, KEY)
check("missing signature rejected when key set", ok == nil and why:find("missing") ~= nil)

local wrongkey = { version = "1", json = "[]", seclang = "" }
wrongkey.sig = sign("other-key", wrongkey)
ok = gr.verify(wrongkey, KEY)
check("signature from another key rejected", ok == nil)

-- unsigned mode: no key configured → accepted, loud warning exactly once
WARNINGS = {}
gr._warned_unsigned = false
check("unsigned pack accepted without key", gr.verify(nosig, nil) == true)
check("unsigned mode warns loudly", #WARNINGS == 1 and WARNINGS[1]:find("UNSIGNED") ~= nil)
gr.verify(nosig, nil)
check("unsigned warning fires once, not per poll", #WARNINGS == 1)

-- version must be covered by the signature (replay of same blobs under a
-- different version string must not verify)
local bumped = { version = "2", json = fields.json, seclang = "", sig = fields.sig }
check("signature does not transfer across versions", gr.verify(bumped, KEY) == nil)

-- ---------------------------------------------------------------------------
print("")
print("build (pack assembly):")
-- ---------------------------------------------------------------------------

local JSON_RULES = [=[[
  {"id":"g_json_b","phase":"access","conditions":[{"op":"contains","value":"x","variables":["request.path"]}],"action":{},"log":false},
  {"id":"g_json_a","phase":"header_filter","conditions":[{"op":"contains","value":"y","variables":["response.header.value"]}],"action":{}},
  {"id":"g_mcp","phase":"mcp_event","conditions":[{"op":"contains","value":"z","variables":["mcp.event.data"]}],"action":{}}
]]=]
local SECLANG_RULES = [[
SecRule REQUEST_URI "@contains attack2" "id:9000902,phase:2,deny,msg:'g2'"
SecRule REQUEST_URI "@contains attack1" "id:9000901,phase:2,deny,msg:'g1'"
]]

local pack, berr = gr.build({ version = "7", json = JSON_RULES, seclang = SECLANG_RULES })
check("build succeeds", pack ~= nil, tostring(berr))
check("counts: 3 json + 2 seclang", pack and pack.n_json == 3 and pack.n_seclang == 2,
      pack and (pack.n_json .. "/" .. pack.n_seclang))
check("json rules keep author order, before seclang",
      pack and pack.all[1].id == "g_json_b" and pack.all[2].id == "g_json_a" and pack.all[3].id == "g_mcp")
check("seclang rules sorted by id (determinism across workers)",
      pack and tostring(pack.all[4].id) == "9000901" and tostring(pack.all[5].id) == "9000902",
      pack and (tostring(pack.all[4].id) .. "," .. tostring(pack.all[5].id)))
check("phase split: access", pack and #pack.access == 3 and pack.access[1].id == "g_json_b")
check("phase split: header_filter", pack and #pack.header_filter == 1 and pack.header_filter[1].id == "g_json_a")
check("phase split: mcp_event", pack and #pack.mcp_event == 1 and pack.mcp_event[1].id == "g_mcp")
check("log defaults to true when unset", pack and pack.all[2].log == true)
check("explicit log:false respected", pack and pack.all[1].log == false)

-- insane rules are dropped loudly, sane ones survive
ERRORS = {}
pack = gr.build({ version = "8", json = '[{"id":"no_phase"},{"id":"ok1","phase":"access","conditions":[]}]', seclang = "" })
check("insane json rule dropped, sane one kept", pack and pack.n_json == 1 and pack.n_dropped == 1 and #ERRORS == 1)

-- unparseable payloads reject the whole pack (caller keeps last known good)
pack, berr = gr.build({ version = "9", json = "{not json", seclang = "" })
check("broken json payload rejects the pack", pack == nil and berr ~= nil)

-- empty pack builds fine
pack = gr.build({ version = "10", json = "", seclang = "" })
check("empty payloads build an empty pack", pack and #pack.all == 0)

-- ---------------------------------------------------------------------------
print("")
print("tick (poll state machine):")
-- ---------------------------------------------------------------------------

-- force config: fake env via direct injection (config() memoizes)
gr._config = { host = "karna-redis", port = 6379, database = 0, poll = 30, hmac_key = KEY }
gr._pack, gr._last_version, gr._last_version_num = nil, nil, nil

local F1 = { version = "1", json = '[{"id":"t1","phase":"access","conditions":[]}]', seclang = "" }
F1.sig = sign(KEY, F1)

reset({ fields = F1 })
local res, terr = gr._tick()
check("first poll applies the pack", res == "applied", tostring(terr))
check("get() exposes it", gr.get() and #gr.get().all == 1 and gr.get().all[1].id == "t1")
check("hgetall fetched after version change", logged("hgetall") ~= nil)

reset({ fields = F1 })
res = gr._tick()
check("same version → unchanged", res == "unchanged")
check("...and no full fetch (cheap poll)", logged("hgetall") == nil)

-- new version, valid sig → applied
local F2 = { version = "2", json = '[{"id":"t2","phase":"access","conditions":[]}]', seclang = "" }
F2.sig = sign(KEY, F2)
reset({ fields = F2 })
check("new version applied", gr._tick() == "applied" and gr.get().all[1].id == "t2")

-- rollback: older signed pack must be refused, last known good kept
reset({ fields = F1 })
res, terr = gr._tick()
check("version rollback refused (replay guard)", res == nil and terr:find("rollback") ~= nil, tostring(terr))
check("last known good pack kept after rollback attempt", gr.get().all[1].id == "t2")

-- tampered pack at a newer version: rejected, last known good kept
local F3 = { version = "3", json = '[{"id":"evil","phase":"access","conditions":[]}]', seclang = "", sig = F2.sig }
reset({ fields = F3 })
res, terr = gr._tick()
check("bad signature rejected", res == nil and terr:find("rejected") ~= nil, tostring(terr))
check("last known good pack kept after bad sig", gr.get().all[1].id == "t2")

-- connection failure: keep last known good
reset({ connect_ok = false })
res, terr = gr._tick()
check("redis outage → error, pack kept", res == nil and gr.get().all[1].id == "t2")

-- deleted hash: absence is a valid state → pack cleared, version reset
reset({ fields = nil })
res = gr._tick()
check("deleted hash clears the pack", res == "cleared" and #gr.get().all == 0)

-- ...and a fresh publish restarting at version 1 is accepted after a clear
reset({ fields = F1 })
check("fresh publish after clear accepted (version counter reset)", gr._tick() == "applied")

-- non-numeric version rejected
local FX = { version = "abc", json = "[]", seclang = "" }
FX.sig = sign(KEY, FX)
gr._last_version = nil
reset({ fields = FX })
res, terr = gr._tick()
check("non-numeric version rejected", res == nil and terr:find("not a number") ~= nil, tostring(terr))

print("")
if failures == 0 then print("ALL PASS"); os.exit(0)
else print(failures .. " FAILURE(S)"); os.exit(1) end
