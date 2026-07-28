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

-- Deterministic fake crypto: sha256 → a djb2 digest (portable, no bitwise ops
-- so it runs on 5.1 through 5.4), hmac → "mac.<key>.<msg>". All-lowercase
-- because verify() hex-normalizes the stored sig with :lower(); the verify
-- logic under test only needs both sides to be pure functions. The digest is
-- content-sensitive rather than length-only so the file-pack fingerprint
-- assertions below mean something.
gr._sha256_hex = function(s)
    s = s or ""
    local h = 5381
    for i = 1, #s do h = (h * 33 + s:byte(i)) % 4294967296 end
    return string.format("%08x%08x", h, #s)
end
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
check("phase split: access", pack and #pack.detection.access == 3 and pack.detection.access[1].id == "g_json_b")
check("phase split: header_filter", pack and #pack.detection.header_filter == 1 and pack.detection.header_filter[1].id == "g_json_a")
check("phase split: mcp_event", pack and #pack.detection.mcp_event == 1 and pack.detection.mcp_event[1].id == "g_mcp")
check("log defaults to true when unset", pack and pack.all[2].log == true)
check("explicit log:false respected", pack and pack.all[1].log == false)

-- insane rules are dropped loudly, sane ones survive
ERRORS = {}
pack = gr.build({ version = "8", json = '[{"id":"no_phase"},{"id":"ok1","phase":"access","conditions":[]}]', seclang = "" })
check("insane json rule dropped, sane one kept", pack and pack.n_json == 1 and pack.n_dropped == 1 and #ERRORS == 1)

-- unparseable payloads reject the whole pack (caller keeps last known good)
pack, berr = gr.build({ version = "9", json = "{not json", seclang = "" })
check("broken json payload rejects the pack", pack == nil and berr ~= nil)

-- an envelope object instead of the bare array is the likely authoring mistake;
-- it must be an error, not a silent zero-rule load
pack, berr = gr.build({ version = "9b", json = '{"rules":[{"id":"e1","phase":"access","conditions":[]}]}', seclang = "" })
check("json object payload rejected with a clear reason",
      pack == nil and berr ~= nil and berr:find("ARRAY") ~= nil, tostring(berr))

-- empty pack builds fine
pack = gr.build({ version = "10", json = "", seclang = "" })
check("empty payloads build an empty pack", pack and #pack.all == 0)

-- ---------------------------------------------------------------------------
print("")
print("controls / detection split:")
-- ---------------------------------------------------------------------------

-- The split is what makes rule ORDER inside a pack irrelevant: exclusions run
-- on the multi-match controls path, so a blocking rule that matches earlier
-- cannot swallow an exclusion declared after it (which is exactly what
-- happened when both lived in one first-terminal-wins list).
local SPLIT_RULES = [=[[
  {"id":"s_block","phase":"access","conditions":[{"op":"contains","value":"a","variables":["request.path"]}],"action":{"fixed_response":{"status_code":403}}},
  {"id":"s_excl","phase":"access","conditions":[{"op":"beginsWith","value":"/wp-admin","variables":["request.path"]}],"rule_control":[{"remove_rule":{"rule_id":"942100"}}]},
  {"id":"s_excl_empty_action","phase":"access","conditions":[{"op":"beginsWith","value":"/api","variables":["request.path"]}],"action":{},"rule_control":[{"engine_off":true}]},
  {"id":"s_excl_with_action","phase":"access","conditions":[{"op":"beginsWith","value":"/x","variables":["request.path"]}],"rule_control":[{"engine_off":true}],"action":{"set_variable":{"type":"shared","name":"k","value":"v"}}},
  {"id":"s_excl_resp","phase":"header_filter","conditions":[{"op":"contains","value":"b","variables":["response.header.value"]}],"rule_control":[{"remove_rule":{"rule_id":"950100"}}]}
]]=]

pack = gr.build({ version = "11", json = SPLIT_RULES, seclang = "" })
check("controls: only rule_control with no action", pack and pack.n_controls == 3,
      pack and tostring(pack.n_controls))
check("detection keeps the rest", pack and pack.n_detection == 2,
      pack and tostring(pack.n_detection))
check("controls.access holds the two access exclusions",
      pack and #pack.controls.access == 2
          and pack.controls.access[1].id == "s_excl"
          and pack.controls.access[2].id == "s_excl_empty_action")
check("an empty action table still counts as an exclusion",
      pack and pack.controls.access[2].id == "s_excl_empty_action")
check("rule_control PLUS a real action stays in detection (side effects survive)",
      pack and #pack.detection.access == 2
          and pack.detection.access[2].id == "s_excl_with_action")
check("controls split per phase too", pack and #pack.controls.header_filter == 1)

-- @pmFromFile is unsupported on this channel: dropped, never parked in the
-- pack as a condition that can never match.
WARNINGS = {}
pack = gr.build({ version = "12", json = [=[[
  {"id":"p1","phase":"access","conditions":[{"op":"pmFromFile","value":"bad-bots.data","variables":["request.header.value:user-agent"]}]},
  {"id":"p2","phase":"access","conditions":[{"op":"!pmFromFile","value":"good.data","variables":["request.path"]}]},
  {"id":"p3","phase":"access","conditions":[{"op":"contains","value":"z","variables":["request.path"]}]}
]]=], seclang = "" })
check("pmFromFile rules dropped (both op spellings)",
      pack and pack.n_json == 1 and pack.n_dropped == 2 and pack.all[1].id == "p3",
      pack and (pack.n_json .. "/" .. pack.n_dropped))
check("...loudly", #WARNINGS == 2 and WARNINGS[1]:find("pmFromFile") ~= nil)

-- A phase this channel never evaluates would be dead weight that looks like
-- coverage; drop it and say so.
WARNINGS = {}
pack = gr.build({ version = "13", json = '[{"id":"bf","phase":"body_filter","conditions":[]}]', seclang = "" })
check("unevaluated phase dropped", pack and #pack.all == 0 and pack.n_dropped == 1)
check("...with the phase named in the warning",
      #WARNINGS == 1 and WARNINGS[1]:find("body_filter") ~= nil)

-- ---------------------------------------------------------------------------
print("")
print("file source (disk pack):")
-- ---------------------------------------------------------------------------

-- Filesystem stubbed through the module's injection points, so the loader is
-- exercised without touching a real disk.
local FS = {}
gr._path_kind = function(path) return FS[path] and FS[path].kind or nil end
gr._read_file = function(path)
    local node = FS[path]
    if not node or node.kind ~= "file" then return nil, "no such file" end
    if node.unreadable then return nil, "permission denied" end
    return node.content
end
gr._list_dir = function(path)
    local node = FS[path]
    if not node or node.kind ~= "directory" then return nil, "not a directory" end
    if node.unlistable then return nil, "permission denied" end
    local names = {}
    for _, n in ipairs(node.entries or {}) do names[#names + 1] = n end
    table.sort(names)
    return names
end

local RULE_A = '[{"id":"f_a","phase":"access","conditions":[{"op":"contains","value":"a","variables":["request.path"]}]}]'
local RULE_B = '[{"id":"f_b","phase":"access","conditions":[{"op":"contains","value":"b","variables":["request.path"]}]}]'

-- single file
FS = { ["/etc/karna/gr.json"] = { kind = "file", content = RULE_A } }
local fpack, ferr = gr.load_file_pack("/etc/karna/gr.json")
check("single file loads", fpack ~= nil and #fpack.all == 1 and fpack.all[1].id == "f_a", tostring(ferr))
check("pack is fingerprinted", fpack and fpack.version and fpack.version:find("^sha256:") ~= nil,
      fpack and tostring(fpack.version))
check("source metadata recorded", fpack and fpack.source == "file" and fpack.files == 1)

-- missing path
fpack, ferr = gr.load_file_pack("/etc/karna/nope.json")
check("missing path is an error, not a crash", fpack == nil and ferr:find("not found") ~= nil, tostring(ferr))

-- unreadable file
FS = { ["/etc/karna/gr.json"] = { kind = "file", content = RULE_A, unreadable = true } }
fpack, ferr = gr.load_file_pack("/etc/karna/gr.json")
check("unreadable file is an error", fpack == nil and ferr:find("cannot read") ~= nil, tostring(ferr))

-- single file with broken JSON: nothing usable came out, so the caller is
-- told and logs "not loaded" instead of silently publishing an empty pack.
FS = { ["/etc/karna/gr.json"] = { kind = "file", content = "{not json" } }
fpack, ferr = gr.load_file_pack("/etc/karna/gr.json")
check("broken single file yields no pack", fpack == nil and ferr ~= nil, tostring(ferr))

-- directory: *.json only, filename order IS evaluation order
FS = {
    ["/etc/karna/gr.d/"] = { kind = "directory", entries = { "10-b.json", "00-a.json" } },
    ["/etc/karna/gr.d/00-a.json"] = { kind = "file", content = RULE_A },
    ["/etc/karna/gr.d/10-b.json"] = { kind = "file", content = RULE_B },
}
FS["/etc/karna/gr.d"] = FS["/etc/karna/gr.d/"]
fpack, ferr = gr.load_file_pack("/etc/karna/gr.d")
check("directory loads every *.json", fpack ~= nil and #fpack.all == 2, tostring(ferr))
check("filename order drives evaluation order",
      fpack and fpack.all[1].id == "f_a" and fpack.all[2].id == "f_b")
check("file count recorded", fpack and fpack.files == 2)

-- one bad file in a directory must not take the good ones down with it
ERRORS = {}
FS["/etc/karna/gr.d"] = { kind = "directory", entries = { "00-a.json", "05-bad.json", "10-b.json" } }
FS["/etc/karna/gr.d/"] = FS["/etc/karna/gr.d"]
FS["/etc/karna/gr.d/05-bad.json"] = { kind = "file", content = "{not json" }
fpack, ferr = gr.load_file_pack("/etc/karna/gr.d")
check("bad file skipped, good files kept", fpack ~= nil and #fpack.all == 2, tostring(ferr))
check("...and reported", #ERRORS == 1 and ERRORS[1]:find("05%-bad%.json") ~= nil,
      ERRORS[1] or "no error logged")

-- empty directory
FS = { ["/etc/karna/empty"] = { kind = "directory", entries = {} } }
FS["/etc/karna/empty/"] = FS["/etc/karna/empty"]
fpack, ferr = gr.load_file_pack("/etc/karna/empty")
check("empty directory is an error", fpack == nil and ferr:find("no %*%.json") ~= nil, tostring(ferr))

-- The fingerprint is what answers "are all my nodes running the same global
-- rules?", so it must follow the bytes and only the bytes.
FS = {
    ["/f1"] = { kind = "file", content = RULE_A },
    ["/f2"] = { kind = "file", content = RULE_B },
    ["/f1-copy"] = { kind = "file", content = RULE_A },
}
local fp1 = gr.load_file_pack("/f1")
local fp2 = gr.load_file_pack("/f2")
local fp1c = gr.load_file_pack("/f1-copy")
check("different content, different fingerprint", fp1.fingerprint ~= fp2.fingerprint)
check("same content, same fingerprint (nodes are comparable)",
      fp1.fingerprint == fp1c.fingerprint)

-- ---------------------------------------------------------------------------
print("")
print("recombine (disk + redis merge, dedup):")
-- ---------------------------------------------------------------------------

local function ids_of(list)
    local out = {}
    for _, r in ipairs(list) do out[#out + 1] = tostring(r.id) end
    return table.concat(out, ",")
end

local DISK = [=[[
  {"id":"d_excl","phase":"access","conditions":[],"rule_control":[{"remove_rule":{"rule_id":"1"}}]},
  {"id":"d_block","phase":"access","conditions":[],"action":{"fixed_response":{"status_code":403}}},
  {"id":"shared_id","phase":"access","conditions":[],"action":{"fixed_response":{"status_code":403}}}
]]=]
local REDIS = [=[[
  {"id":"r_excl","phase":"access","conditions":[],"rule_control":[{"remove_rule":{"rule_id":"2"}}]},
  {"id":"r_block","phase":"access","conditions":[],"action":{"fixed_response":{"status_code":403}}},
  {"id":"shared_id","phase":"access","conditions":[],"action":{"fixed_response":{"status_code":418}}}
]]=]

WARNINGS = {}
gr._file_pack = gr.build({ version = "sha256:disk", json = DISK, seclang = "" })
gr._redis_pack = gr.build({ version = "9", json = REDIS, seclang = "" })
local combined = gr.recombine()

check("controls come from both sources, disk first",
      ids_of(combined.controls.access) == "d_excl,r_excl", ids_of(combined.controls.access))
check("detection comes from both sources, disk first",
      ids_of(combined.detection.access) == "d_block,shared_id,r_block",
      ids_of(combined.detection.access))
check("duplicate id: disk wins, redis copy discarded", combined.n_duplicates == 1
      and combined.duplicate_ids[1] == "shared_id")
check("...loudly", #WARNINGS == 1 and WARNINGS[1]:find("duplicate rule id shared_id") ~= nil,
      WARNINGS[1] or "no warning")
check("the surviving rule is the disk one",
      combined.detection.access[2].action.fixed_response.status_code == 403)
check("get() serves the merged pack", gr.get() == combined)

-- disk-only: works with no Redis at all
gr._redis_pack = nil
combined = gr.recombine()
check("disk source works alone", ids_of(combined.detection.access) == "d_block,shared_id")

-- redis-only: unchanged behaviour when no file is configured
gr._file_pack = nil
gr._redis_pack = gr.build({ version = "9", json = REDIS, seclang = "" })
combined = gr.recombine()
check("redis source works alone", ids_of(combined.detection.access) == "r_block,shared_id")

-- ---------------------------------------------------------------------------
print("")
print("tick (poll state machine):")
-- ---------------------------------------------------------------------------

-- force config: fake env via direct injection (config() memoizes)
gr._config = { host = "karna-redis", port = 6379, database = 0, poll = 30, hmac_key = KEY }
gr._file_pack, gr._redis_pack, gr._combined = nil, nil, nil
gr._last_version, gr._last_version_num = nil, nil

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
