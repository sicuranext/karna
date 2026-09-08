-- ka-unittest/audit_request_body_control.lua
--
-- Guards the `audit_request_body` rule control (ModSecurity
-- `ctl:auditLogParts=+C`): when a matching rule applies it, the raw request
-- body is attached to the audit record of that request — IF a record is
-- written. Pure enrichment: not a match, no forced write, no status change.
--
-- Load-bearing properties pinned here:
--   1. the SecLang parser emits `{audit_request_body = true}` for `+C` (and for
--      a full part list containing C), nothing for `-C`, other letters or
--      ctl:auditEngine, and picks the ctl up from the last link of a chain;
--   2. a JSON rule carrying only the control (no action) is a control-only rule
--      → multi-match controls path, never recorded in matches[] / messages[];
--   3. the applier sets the flag (strict `== true`) and touches nothing else;
--   4. the body block: clipped at the cap (default 16384) with `body_truncated`
--      and the original `body_length`; a clip that split a multi-byte character
--      backs off instead of turning text into base64; a body that is not valid
--      UTF-8 is base64-encoded and marked `body_encoding = "base64"`;
--   5. placement: v2 `request.body_raw` (+ body_encoding / body_truncated /
--      body_length), v1 `transaction.request.body` (ModSecurity's part C slot);
--      nothing is attached without the flag, under body_access_off, or when
--      the engine never pinned a body; matches[] / messages[] are untouched;
--   6. the control does not satisfy `auditlog_only_on_match`.
--
-- (1), (4), (5) run against the REAL seclang.lua / ka_utils.lua behind stubs.
-- (2), (3), (6) are inline copies (same convention as rule_control_runtime.lua /
-- log_only_action.lua). KEEP IN SYNC with:
--   kong/plugins/karna/modules/ka_compile.lua  is_control_only
--   kong/plugins/karna/modules/ka_engine.lua   __apply_rule_controls_inline
--   kong/plugins/karna/handler.lua             log (the loggable_matches /
--                                              auditlog_only_on_match gate)
--
-- Fixtures are synthetic: example.com, x-upstream-* headers, 9999xx rule ids.
--
-- Run from repo root:
--   lua    ka-unittest/audit_request_body_control.lua
--   luajit ka-unittest/audit_request_body_control.lua

package.path = "./kong/plugins/karna/modules/?.lua;" .. package.path
package.preload["inspect"] = function() return function() return "" end end

local fails = 0
local function ok(cond, name)
    if cond then print("  ok  - " .. name)
    else print("  FAIL- " .. name); fails = fails + 1 end
end
local function find(tbl, pred)
    for _, v in ipairs(tbl or {}) do if pred(v) then return v end end
    return nil
end
local function has_control(controls, key)
    return find(controls, function(c) return c[key] == true end) ~= nil
end
local function keyset(t)
    local ks = {}
    for k in pairs(t) do ks[#ks + 1] = tostring(k) end
    table.sort(ks)
    return table.concat(ks, ",")
end

-- ============================================================
print("- SecLang: ctl:auditLogParts=+C")
-- ============================================================
local seclang = require("seclang")

local c = seclang.__get_rule_controls("id:999910,phase:2,pass,nolog,ctl:auditLogParts=+C")
ok(has_control(c, "audit_request_body") and #c == 1, "+C → audit_request_body, nothing else")
c = seclang.__get_rule_controls("id:999911,phase:2,pass,nolog,ctl:auditLogParts=+E")
ok(#c == 0, "+E (another part) → ignored")
c = seclang.__get_rule_controls("id:999912,phase:2,pass,nolog,ctl:auditLogParts=-C")
ok(#c == 0, "-C → ignored (the body is off by default; nothing to remove)")
c = seclang.__get_rule_controls("id:999913,phase:2,pass,nolog,ctl:auditLogParts=ABCFHZ")
ok(has_control(c, "audit_request_body"), "a full part list that contains C counts")
c = seclang.__get_rule_controls("id:999914,phase:2,pass,nolog,ctl:auditLogParts=ABFHZ")
ok(#c == 0, "a full part list without C → ignored")
c = seclang.__get_rule_controls("id:999915,phase:2,pass,nolog,ctl:auditLogParts=+CE")
ok(has_control(c, "audit_request_body"), "+CE → C is in the added set")
c = seclang.__get_rule_controls("id:999916,phase:2,pass,nolog,ctl:auditEngine=On")
ok(#c == 0, "ctl:auditEngine=* stays ignored")
c = seclang.__get_rule_controls("id:999917,phase:2,pass,nolog,ctl:auditEngine=Off,ctl:auditLogParts=+C,ctl:auditLogParts=+E")
ok(has_control(c, "audit_request_body") and #c == 1,
   "several auditLogParts directives → the control is emitted once")
c = seclang.__get_rule_controls("id:999918,phase:2,pass,nolog,ctl:auditLogParts=+C,ctl:requestBodyAccess=Off")
ok(has_control(c, "audit_request_body") and has_control(c, "body_access_off"),
   "coexists with other ctl:* (the runtime, not the parser, decides that body_access_off wins)")

print("- SecLang: the ModSecurity shape — a pass rule keyed on method + path, ctl on the last link")
local parsed = seclang.parse_isolated([[
SecRule REQUEST_METHOD "@streq POST" \
    "id:999919,phase:2,pass,nolog,t:none,chain"
    SecRule REQUEST_URI "@beginsWith /api/orders" "t:none,ctl:auditLogParts=+C"
]])
local r = parsed["999919"]
ok(r ~= nil, "chain parsed")
ok(r and has_control(r.rule_control, "audit_request_body"), "+C on the last link lands on the head")
ok(r and #r.conditions == 2, "two conditions (method AND path)")
ok(r and r.log == false, "nolog honoured: even if it were recorded, it would not be written")
ok(r and r.action and r.action.fixed_response == nil, "pass → no terminal action")

-- ============================================================
print("")
print("- the JSON shape is a control-only rule → controls path, never a match")
-- ============================================================
-- SUT — copy of ka_compile.is_control_only (canonical) / ka_global_rules duplicate
local function is_control_only(rule)
    if type(rule.rule_control) ~= "table" then return false end
    local action = rule.action
    if action == nil then return true end
    if type(action) ~= "table" then return false end
    return next(action) == nil
end

local json_rule = {
    id = "999910", phase = "access",
    conditions = {
        { variables = { "request.method" }, op = "eq", value = "POST" },
        { variables = { "request.path" },   op = "beginsWith", value = "/api/orders" },
    },
    rule_control = { { audit_request_body = true } },
}
ok(is_control_only(json_rule), "no action + rule_control → controls (multi-match) path")
ok(not is_control_only({ id = "999920", conditions = {}, rule_control = { { audit_request_body = true } },
                         action = { fixed_response = { status_code = 403 } } }),
   "with a real action next to it → detection path (the body then rides on the block record)")

-- ============================================================
print("")
print("- applier (inline copy)")
-- ============================================================
local function new_store()
    return {
        ids = {}, ids_targets = {}, tags = {}, removed_tags = {},
        remove_target_from_all_rules = {},
        engine_off = false, detection_only = false, engine_on = false,
        body_access_off = false, audit_request_body = false,
    }
end
-- SUT — copy of ka_engine.lua:__apply_rule_controls_inline (state directives)
local function apply_rule_controls(rc, controls, rule_id)
    if not controls or not rc then return end
    for _, control in pairs(controls) do
        if control.detection_only then
            rc.detection_only = true; rc.engine_on = false; rc.engine_forced_by = nil
        end
        if control.engine_on == true then
            rc.engine_on = true; rc.detection_only = false
            if rule_id ~= nil then rc.engine_forced_by = tostring(rule_id) end
        end
        if control.body_access_off then rc.body_access_off = true end
        if control.audit_request_body == true then rc.audit_request_body = true end
        if control.engine_off then rc.engine_off = true end
    end
    if rc.engine_off and rc.engine_on then rc.engine_on = false; rc.engine_forced_by = nil end
end

local rc = new_store()
ok(rc.audit_request_body == false, "off by default")
apply_rule_controls(rc, json_rule.rule_control, json_rule.id)
ok(rc.audit_request_body == true, "applier set the flag")
ok(rc.engine_on == false and rc.detection_only == false and rc.engine_off == false
   and rc.body_access_off == false, "…and touched nothing else")
rc = new_store()
apply_rule_controls(rc, { { audit_request_body = "yes" } }, "999910")
ok(rc.audit_request_body == false, "audit_request_body = \"yes\" does NOT opt in (strict == true)")

-- ============================================================
print("")
print("- body block + placement (real ka_utils behind stubs)")
-- ============================================================
-- pure-Lua base64, standing in for ngx.encode_base64
local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local function b64(data)
    return ((data:gsub(".", function(x)
        local r, b = "", x:byte()
        for i = 8, 1, -1 do r = r .. (b % 2 ^ i - b % 2 ^ (i - 1) > 0 and "1" or "0") end
        return r
    end) .. "0000"):gsub("%d%d%d?%d?%d?%d?", function(x)
        if #x < 6 then return "" end
        local n = 0
        for i = 1, 6 do n = n + (x:sub(i, i) == "1" and 2 ^ (6 - i) or 0) end
        return B64:sub(n + 1, n + 1)
    end) .. ({ "", "==", "=" })[#data % 3 + 1])
end

local CJSON = { empty_array = coroutine.create(function() end) }
package.preload["cjson"] = function() return CJSON end
package.preload["kong.plugins.karna.version"] = function()
    return { version = "0.0.0-test", commit = "deadbee", commit_short = "deadbee", built_at = "test" }
end
_G.ngx = {
    re = { match = function() return nil end },
    now = function() return 1700000000.5 end,
    time = function() return 1700000000 end,
    var = { request_id = "req-0002", remote_addr = "203.0.113.7", remote_port = "51234",
            server_addr = "10.0.0.1", server_port = "8000", server_id = "srv-1",
            request_time = "0.030", upstream_response_time = "0.020", bytes_sent = "512" },
    log = function() end,
    worker = { id = function() return 0 end },
    encode_base64 = b64,
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
        get_headers         = function() return { host = "api.example.com", ["content-type"] = "application/json",
                                                   ["x-upstream-marker"] = "t2" } end,
        get_path_with_query = function() return "/api/orders" end,
        get_method          = function() return "POST" end,
        get_http_version    = function() return 1.1 end,
    },
    response = {
        get_status  = function() return 200 end,
        get_headers = function() return { ["content-type"] = "application/json" } end,
    },
    service = { response = {
        get_status  = function() return 200 end,
        get_headers = function() return {} end,
    } },
}
local utils = dofile("./kong/plugins/karna/modules/ka_utils.lua")
local build = utils.build_audit_request_body

print("- build_audit_request_body")
ok(build(nil) == nil and build("") == nil and build(42) == nil, "nothing to attach → nil")

local blk = build('{"order":"o-1","note":"héllo"}', 16384)
ok(blk.body == '{"order":"o-1","note":"héllo"}', "small UTF-8 body kept verbatim")
ok(blk.encoding == "utf-8" and blk.truncated == false and blk.length == 31,
   "utf-8 / not truncated / length is the byte count (é is two bytes)")

blk = build(("x"):rep(20000), nil)
ok(#blk.body == 16384 and blk.truncated == true and blk.length == 20000,
   "no cap given → 16384 default, clipped, original length kept")
blk = build(("x"):rep(20000), -5)
ok(#blk.body == 16384, "negative cap → default")
blk = build("a=" .. ("x"):rep(100), 64)
ok(#blk.body == 64 and blk.truncated == true and blk.length == 102 and blk.encoding == "utf-8",
   "cap 64 → 64-byte prefix, truncated, length 102")
blk = build("abc", 3)
ok(blk.body == "abc" and blk.truncated == false, "body exactly at the cap is not truncated")
blk = build("abcd", 0)
ok(blk.body == "" and blk.truncated == true and blk.length == 4 and blk.encoding == "utf-8",
   "cap 0 → record the length only")

print("- a clip that splits a multi-byte character backs off instead of going base64")
local odd = "ab=" .. ("é"):rep(40)             -- 3 + 80 bytes; a 64-byte cut lands mid-é
blk = build(odd, 64)
ok(blk.encoding == "utf-8", "still utf-8")
ok(#blk.body == 63 and blk.body == "ab=" .. ("é"):rep(30), "backed off one byte to the character boundary")
ok(blk.truncated == true and blk.length == 83, "truncated, original length kept")
blk = build("a=" .. ("€"):rep(30), 8)            -- € is 3 bytes; cut at 8 = 2 + 3 + 3 → clean boundary
ok(#blk.body == 8 and blk.encoding == "utf-8", "a cut on a boundary needs no back-off")
blk = build("a=" .. ("€"):rep(30), 9)            -- 9 = boundary + 1 → back off 1
ok(#blk.body == 8 and blk.encoding == "utf-8", "one byte into a 3-byte char → back off to 8")
blk = build("a=" .. ("€"):rep(30), 10)           -- boundary + 2 → back off 2
ok(#blk.body == 8 and blk.encoding == "utf-8", "two bytes into a 3-byte char → back off to 8")

print("- not valid UTF-8 → base64, marked")
blk = build("a=\195(\255", 16384)
ok(blk.encoding == "base64", "encoding = base64")
ok(blk.body == "YT3DKP8=", "the bytes, base64-encoded (a=\\xc3(\\xff)")
ok(blk.truncated == false and blk.length == 5, "not truncated, length is the raw byte count")
blk = build(("\255"):rep(100), 10)
ok(blk.encoding == "base64" and blk.body == b64(("\255"):rep(10)) and blk.truncated == true and blk.length == 100,
   "binary AND over the cap → base64 of the clipped prefix, truncated")
blk = build("\0\1\2ok", 16384)
ok(blk.encoding == "utf-8" and blk.body == "\0\1\2ok",
   "control bytes are valid UTF-8 → kept (cjson escapes them on write)")

print("- attach: v2")
local CONF = { engine_blocking_mode = false, paranoia_level = 1, auditlog_request_body_max_bytes = 16384 }
kong.ctx.plugin = {
    rule_controls = { audit_request_body = true, body_access_off = false, engine_on = false, detection_only = false },
    ka_raw_body   = '{"order":"o-1","note":"héllo"}',
}
local v2 = utils:get_auditlog_v2({}, CONF)
local before_req = keyset(v2.request)
local before_top = keyset(v2)
ok(utils:attach_audit_request_body(v2, CONF) == true, "attached (returns true)")
ok(v2.request.body_raw == '{"order":"o-1","note":"héllo"}', "request.body_raw is the body as received")
ok(v2.request.body_encoding == "utf-8" and v2.request.body_truncated == false and v2.request.body_length == 31,
   "request.body_encoding / body_truncated / body_length next to it")
ok(keyset(v2.request) == before_req .. ",body_encoding,body_length,body_raw,body_truncated"
   or keyset(v2.request) == table.concat((function()
        local ks = {}
        for k in (before_req .. ",body_encoding,body_length,body_raw,body_truncated"):gmatch("[^,]+") do ks[#ks + 1] = k end
        table.sort(ks)
        return ks end)(), ","),
   "request block gained exactly those four keys")
ok(keyset(v2) == before_top, "no new top-level key")
ok(v2.matches == CJSON.empty_array, "matches[] untouched (still the empty sentinel: not a match)")
ok(v2.response.status == 200, "status untouched")

print("- attach: v2 honours auditlog_request_body_max_bytes")
kong.ctx.plugin.ka_raw_body = "a=" .. ("x"):rep(100)
v2 = utils:get_auditlog_v2({}, CONF)
utils:attach_audit_request_body(v2, { auditlog_request_body_max_bytes = 4 })
ok(v2.request.body_raw == "a=xx" and v2.request.body_truncated == true and v2.request.body_length == 102,
   "clipped at the configured cap")
v2 = utils:get_auditlog_v2({}, CONF)
utils:attach_audit_request_body(v2, {})
ok(#v2.request.body_raw == 102 and v2.request.body_truncated == false, "no cap in conf → default 16384")

print("- attach: v1 (ModSecurity part C slot)")
kong.ctx.plugin.ka_raw_body = '{"order":"o-1"}'
local v1 = utils:get_auditlog(nil, nil)
local before_v1 = keyset(v1.transaction.request)
ok(utils:attach_audit_request_body(v1, CONF) == true, "attached")
ok(v1.transaction.request.body == '{"order":"o-1"}', "transaction.request.body — where a ModSecurity consumer looks")
ok(v1.transaction.request.body_encoding == "utf-8" and v1.transaction.request.body_truncated == false
   and v1.transaction.request.body_length == 15, "same three siblings")
ok(v1.transaction.messages == CJSON.empty_array, "messages[] untouched")
ok(v1.transaction.request.body_raw == nil, "no v2 key leaked into v1")
v1 = utils:get_auditlog(nil, nil)
ok(keyset(v1.transaction.request) == before_v1, "a fresh v1 document has none of the four keys before attach")

print("- attach: when NOT to")
kong.ctx.plugin = { rule_controls = { audit_request_body = false, body_access_off = false }, ka_raw_body = "a=1" }
v2 = utils:get_auditlog_v2({}, CONF)
local ks = keyset(v2.request)
ok(utils:attach_audit_request_body(v2, CONF) == false and keyset(v2.request) == ks,
   "flag not set → nothing (a body was read for inspection, but nobody asked to log it)")

kong.ctx.plugin = { rule_controls = { audit_request_body = true, body_access_off = true }, ka_raw_body = "a=1" }
v2 = utils:get_auditlog_v2({}, CONF)
ok(utils:attach_audit_request_body(v2, CONF) == false and v2.request.body_raw == nil,
   "body_access_off active → nothing (part C is unavailable with body access off)")

kong.ctx.plugin = { rule_controls = { audit_request_body = true, body_access_off = false }, ka_raw_body = false }
v2 = utils:get_auditlog_v2({}, CONF)
ok(utils:attach_audit_request_body(v2, CONF) == false and v2.request.body_raw == nil,
   "engine read no body (false sentinel: GET, empty body) → nothing")
kong.ctx.plugin = { rule_controls = { audit_request_body = true, body_access_off = false } }
v2 = utils:get_auditlog_v2({}, CONF)
ok(utils:attach_audit_request_body(v2, CONF) == false, "engine never read the body (nil) → nothing")
kong.ctx.plugin = { rule_controls = { audit_request_body = "yes", body_access_off = false }, ka_raw_body = "a=1" }
v2 = utils:get_auditlog_v2({}, CONF)
ok(utils:attach_audit_request_body(v2, CONF) == false, "flag must be exactly true")
kong.ctx.plugin = {}
v2 = utils:get_auditlog_v2({}, CONF)
ok(utils:attach_audit_request_body(v2, CONF) == false, "no rule_controls store at all (early-exit request) → nothing, no error")
ok(utils:attach_audit_request_body(nil, CONF) == false, "nil document → false, no error")

-- ============================================================
print("")
print("- does not force a write (inline copy of the handler's log gate)")
-- ============================================================
-- SUT — copy from handler.lua:log
local function loggable(collected)
    local out = {}
    for _, m in ipairs(collected) do if m.rule.log then out[#out + 1] = m end end
    return out
end
local function would_write(collected, only_on_match, has_external)
    if only_on_match and #loggable(collected) == 0 and not has_external then return false end
    return true
end
-- the control-only rule runs on the controls path: nothing is collected
local collected = {}
ok(would_write(collected, false, false) == true, "auditlog_only_on_match=false → record written, body rides on it")
ok(would_write(collected, true, false) == false,
   "auditlog_only_on_match=true, nothing else matched → NO record (the control does not force one)")
collected = { { rule = json_rule } }
ok(#loggable(collected) == 0,
   "even if the control rule were collected, it has no `log` → it would not count as a match")

print(string.format("\n%d test(s) failed", fails))
os.exit(fails == 0 and 0 or 1)
