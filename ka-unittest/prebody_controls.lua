-- ka-unittest/prebody_controls.lua
--
-- The pre-body rule-controls pass: control-only access rules whose conditions
-- never read the request body run BEFORE the three body gates (content-type
-- enforce, body parser, argument count), so a `ctl:requestBodyAccess=Off`
-- keyed on the path or a header takes the body out of those gates and the
-- body is never parsed for that request. ModSecurity phase 1.
--
-- Why this exists: a shop endpoint receiving legitimate 20 000-argument forms
-- was blocked by `limit_arg_num`; raising the limit made every such request
-- parse the body (~3 MB) and run the RE2 pre-pass over 40 000 values (~26 MB)
-- BEFORE the operator's `ctl:requestBodyAccess=Off` rule could run, and the
-- worker heap oscillated at 4x its baseline. With the pass in front of the
-- gates the same request allocates ~0.1 MB.
--
-- Pinned here, against the REAL modules (seclang, ka_compile, ka_engine,
-- ka_global_rules, handler.lua behind the harness stubs):
--
--   1. seclang no longer emits an empty `setvar` list, so a `pass,ctl:*` rule
--      has an empty action and `is_control_only` files it as a control. It used
--      to start every action as `{setvar = {}}`, which sent EVERY SecLang
--      exclusion to the detection list — where the RE2 pre-pass ran first.
--   2. ka_compile.is_prebody_var / is_prebody_control: the allow-list of
--      body-free variables (ARGS is body-bearing; request.body.processor is
--      not), and the rule-level classification after compile_rules.
--   3. the three body gates honour body_access_off: nothing parsed, nothing
--      counted, nothing blocked, the raw body never read — and still fire
--      without it.
--   4. the split in the global pack (controls_prebody, after compile; nothing
--      moves without a compiler; recombine carries the slot).
--   5. the split in handler.lua for custom_secrules and rules_request, through
--      the plugin._internals seam.
--
-- Run from repo root:
--   lua    ka-unittest/prebody_controls.lua
--   luajit ka-unittest/prebody_controls.lua

local H = dofile("./ka-unittest/_engine_harness.lua")
local engine     = H.engine
local ka_compile = H.ka_compile

-- The real SecLang parser (the harness stubs kong.plugins.karna.ka_seclang for
-- the engine's own CRS loader; handler.lua and ka_global_rules get the real one
-- below).
local seclang = require("seclang")
package.loaded["kong.plugins.karna.ka_seclang"] = seclang
-- ka_global_rules is not on the harness's module map (the engine never loads
-- it); it requires cjson, resty.redis and ka_seclang, all of which are in place.
package.preload["kong.plugins.karna.ka_global_rules"] = function()
    return dofile("./kong/plugins/karna/modules/ka_global_rules.lua")
end

local fails = 0
local function ok(cond, name, detail)
    if cond then print("  ok  - " .. name)
    else print("  FAIL- " .. name .. (detail and ("  (" .. tostring(detail) .. ")") or "")); fails = fails + 1 end
end
local function count(t) local n = 0; if type(t) == "table" then for _ in pairs(t) do n = n + 1 end end; return n end
local function ids(list)
    local out = {}
    for _, r in ipairs(list or {}) do out[#out + 1] = tostring(r.id) end
    return table.concat(out, ",")
end
local function parse_one(raw)
    local parsed = seclang.parse_isolated(raw)
    local _, rule = next(parsed)
    return rule
end

local SEC_OFF   = 'SecRule REQUEST_URI "@rx ^/[a-z]{2}/api/catalog/price-lookup" "id:10001010,phase:1,pass,nolog,ctl:requestBodyAccess=Off"'
-- Same rule on @beginsWith for the end-to-end match below: the harness stubs
-- ngx.re.match (and RE2) to "no match", so @rx cannot fire under it.
local SEC_OFF_BW = 'SecRule REQUEST_URI "@beginsWith /it/api/catalog/price-lookup" "id:10001011,phase:1,pass,nolog,ctl:requestBodyAccess=Off"'
local SEC_ARGS  = 'SecRule ARGS:debug "@streq 1" "id:10001020,phase:2,pass,nolog,ctl:ruleRemoveById=942100"'
local SEC_DENY  = 'SecRule REQUEST_URI "@beginsWith /admin" "id:10001030,phase:1,deny,status:403"'
local SEC_SETV  = 'SecRule REQUEST_URI "@beginsWith /x" "id:10001040,phase:1,pass,nolog,setvar:\'tx.marker=1\',ctl:ruleRemoveById=942100"'

-- ============================================================
print("\n1. seclang: a pass,ctl:* rule has an EMPTY action (no phantom setvar)")
-- ============================================================
local r_off = parse_one(SEC_OFF)
ok(r_off ~= nil and r_off.id == "10001010", "rule parsed", r_off and r_off.id)
ok(r_off and type(r_off.action) == "table" and next(r_off.action) == nil,
   "action is an empty table (no setvar key)", r_off and r_off.action and count(r_off.action))
ok(r_off and ka_compile.is_control_only(r_off) == true, "is_control_only → true")
ok(r_off and r_off.rule_control and r_off.rule_control[1] and r_off.rule_control[1].body_access_off == true,
   "ctl:requestBodyAccess=Off → body_access_off")
ok(r_off and r_off.phase == "access", "phase:1 → access")

local r_setv = parse_one(SEC_SETV)
ok(r_setv and r_setv.action.setvar and #r_setv.action.setvar == 1
   and r_setv.action.setvar[1].var_name == "marker" and r_setv.action.setvar[1].var_value == "1",
   "setvar: is still emitted when declared")
ok(r_setv and ka_compile.is_control_only(r_setv) == false,
   "a rule carrying setvar stays out of the controls bucket (side effect must run)")

local r_deny = parse_one(SEC_DENY)
ok(r_deny and r_deny.action.fixed_response and r_deny.action.fixed_response.status_code == 403
   and r_deny.action.setvar == nil, "deny → fixed_response only, no setvar")
ok(r_deny and ka_compile.is_control_only(r_deny) == false, "deny rule is detection")

-- ============================================================
print("\n2. ka_compile.is_prebody_var — body-free variables only")
-- ============================================================
local PRE = {
    "request.path", "request.raw_path", "request.path_with_query", "request.raw_query",
    "request.method", "request.host", "request.line", "request.basename",
    "request.remote_addr", "request.forwarded_addr", "remote_addr",
    "request.header.value", "request.header.value:content-type", "request.header.name:x-foo",
    "request.header_no_fp.value:x-foo", "request.header.referer.host",
    "request.cookie.value", "request.cookie.value:session", "request.cookie.name",
    "request.query.value", "request.query.value:id", "request.query.name",
    "request.body.processor", "tx:crs_validate_utf8_encoding", "var:foo",
    "geoip.country_code", "asn.id", "tls.sni", "redis.banned", "connection.id",
    "matched.value", "count:request.header.value:x-foo", "count:request.cookie.value",
}
local BODY = {
    "request.arg.value", "request.arg.value:id", "request.arg.name",
    "request.body", "request.body.value", "request.body.length",
    "request.body.urlencode.value", "request.body.urlencode.value:id",
    "request.body.json.value", "request.body.xml.value", "request.body.multipart.name",
    "request.file", "request.file.name", "count:request.arg.value", "count:request.body.multipart.name",
    "mcp.method", "response.status", "not.a.variable", "", 42,
}
local all_pre, all_body = true, true
for _, v in ipairs(PRE)  do if not ka_compile.is_prebody_var(v) then all_pre  = false; print("      not pre-body: " .. v) end end
for _, v in ipairs(BODY) do if ka_compile.is_prebody_var(v)     then all_body = false; print("      wrongly pre-body: " .. tostring(v)) end end
ok(all_pre,  #PRE .. " body-free variables are pre-body")
ok(all_body, #BODY .. " body-bearing / unknown variables are not")

-- ============================================================
print("\n3. ka_compile.is_prebody_control — after compile_rules")
-- ============================================================
local function ctl(id, phase, conditions, extra)
    local r = { id = id, phase = phase, conditions = conditions,
                rule_control = { { remove_rule = { rule_id = "942100" } } } }
    for k, v in pairs(extra or {}) do r[k] = v end
    return r
end
local function cond(vars, op, value)
    return { variables = vars, op = op or "beginsWith", value = value or "/", transform = {} }
end
local R = {
    path      = ctl("c_path",  "access", { cond({ "request.path" }) }),
    args      = ctl("c_args",  "access", { cond({ "request.arg.value" }, "rx", "x") }),
    body      = ctl("c_body",  "access", { cond({ "request.body.urlencode.value" }, "rx", "x") }),
    hdr_ck    = ctl("c_hdr",   "access", { cond({ "request.header.value:content-type", "request.cookie.value" }, "rx", "x") }),
    mixed     = ctl("c_mixed", "access", { cond({ "request.path", "request.arg.value" }, "rx", "x") }),
    action    = ctl("c_act",   "access", { cond({ "request.path" }) },
                    { action = { fixed_response = { status_code = 403 } } }),
    resp      = ctl("c_resp",  "header_filter", { cond({ "request.path" }) }),
    chain     = ctl("c_chain", "access", { cond({ "request.path" }, "rx", "^/(a)"), cond({ "matched.value" }, "rx", "a") }),
    cnt_hdr   = ctl("c_cnt",   "access", { cond({ "count:request.header.value:x-foo" }, "gt", "0") }),
    cnt_args  = ctl("c_cnta",  "access", { cond({ "count:request.arg.value" }, "gt", "0") }),
    proc      = ctl("c_proc",  "access", { cond({ "request.body.processor" }, "eq", "JSON") }),
    len       = ctl("c_len",   "access", { cond({ "request.body.length" }, "gt", "0") }),
    nocond    = ctl("c_none",  "access", {}),
    setvar    = ctl("c_setvar","access", { cond({ "request.path" }) }, { action = { setvar = { { var_name = "a", var_value = "1" } } } }),
}
local uncompiled = ctl("c_raw", "access", { cond({ "request.path" }) })
local list = {}
for _, r in pairs(R) do list[#list + 1] = r end
ka_compile.compile_rules(list, nil)

ok(ka_compile.is_prebody_control(R.path)    == true,  "path-only control → pre-body")
ok(ka_compile.is_prebody_control(R.hdr_ck)  == true,  "header + cookie control → pre-body")
ok(ka_compile.is_prebody_control(R.chain)   == true,  "chain on path + matched.value → pre-body")
ok(ka_compile.is_prebody_control(R.cnt_hdr) == true,  "&REQUEST_HEADERS:x → pre-body")
ok(ka_compile.is_prebody_control(R.proc)    == true,  "REQBODY_PROCESSOR (Content-Type derived) → pre-body")
ok(ka_compile.is_prebody_control(R.args)    == false, "ARGS control → not pre-body (ARGS parses the body)")
ok(ka_compile.is_prebody_control(R.body)    == false, "body namespace control → not pre-body")
ok(ka_compile.is_prebody_control(R.mixed)   == false, "one body-bearing variable in the list → not pre-body")
ok(ka_compile.is_prebody_control(R.cnt_args)== false, "&ARGS → not pre-body")
ok(ka_compile.is_prebody_control(R.len)     == false, "REQUEST_BODY_LENGTH → not pre-body (reads the bytes)")
ok(ka_compile.is_prebody_control(R.action)  == false, "control + terminal action → not pre-body (detection)")
ok(ka_compile.is_prebody_control(R.setvar)  == false, "control + setvar → not pre-body (side effect)")
ok(ka_compile.is_prebody_control(R.resp)    == false, "header_filter control → not pre-body")
ok(ka_compile.is_prebody_control(R.nocond)  == false, "no conditions → not pre-body")
ok(ka_compile.is_prebody_control(uncompiled) == false, "uncompiled rule → not pre-body (flag is a compiler output)")
ok(R.path._prebody == true and R.args._prebody == false, "_prebody flag set by compile_rules")

-- the shop rule, end to end through the parser + compiler
ka_compile.compile_rules({ r_off }, nil)
ok(ka_compile.is_prebody_control(r_off) == true,
   "SecRule REQUEST_URI ... phase:1,pass,ctl:requestBodyAccess=Off → pre-body control")
local r_args = parse_one(SEC_ARGS)
ka_compile.compile_rules({ r_args }, nil)
ok(ka_compile.is_control_only(r_args) == true and ka_compile.is_prebody_control(r_args) == false,
   "SecRule ARGS:debug ... pass,ctl → control, but not pre-body")

-- ============================================================
print("\n4. the body gates honour body_access_off (and still fire without it)")
-- ============================================================
local function request(ct, body, raw_query)
    H.request.method    = "POST"
    H.request.path      = "/it/api/catalog/price-lookup"
    H.request.raw_path  = "/it/api/catalog/price-lookup"
    H.request.raw_query = raw_query or ""
    H.request.headers   = { ["Content-Type"] = ct, ["Content-Length"] = tostring(#body) }
    H.request.body      = body
end
local function fresh(off)
    local rc = H.reset()
    kong.ctx.plugin.ka_matched_rules = {}
    rc.body_access_off = off
    return rc
end
local function matched_ids()
    local out = {}
    for _, m in ipairs(kong.ctx.plugin.ka_matched_rules) do out[#out + 1] = m.rule.id end
    return table.concat(out, ",")
end
local CONF = {
    engine_blocking_mode = false,        -- detection: gates record and return, no response_exit
    limit_arg_num = 2,
    try_bas64decode_if_possible = false,
    request_content_type_enforce = true,
    request_content_type_allowed = { "application/x-www-form-urlencoded", "application/json" },
}

-- 4a. argument count
request("application/x-www-form-urlencoded", "a=1&b=2&c=3&d=4&e=5", "q=1")
fresh(true)
local over = engine:check_request_arg_count(CONF)
ok(over == false, "arg count under body_access_off: only the query is counted (1 <= 2)")
ok(kong.ctx.plugin.ka_raw_body == nil, "raw body never read under body_access_off")
ok(matched_ids() == "", "no limit_arg_num entry", matched_ids())
ok(kong.ctx.plugin.body_values_cache and count(kong.ctx.plugin.body_values_cache["raw:nobody"] or {}) == 0
   and kong.ctx.plugin.body_values_cache["raw"] == nil,
   "body cache holds only the empty :nobody entry, nothing parsed")

fresh(false)
over = engine:check_request_arg_count(CONF)
ok(over == true, "same request without the control: 6 > 2 → over the limit")
ok(matched_ids() == "limit_arg_num", "limit_arg_num entry recorded", matched_ids())
ok(kong.ctx.plugin.ka_raw_body ~= nil, "body was read and parsed without the control")

-- 4b. body parser (malformed JSON)
request("application/json", '{"a":1')
fresh(true)
engine:check_request_body_parser(CONF)
ok(matched_ids() == "" and kong.ctx.plugin.ka_raw_body == nil,
   "malformed JSON under body_access_off: not parsed, not blocked", matched_ids())
fresh(false)
engine:check_request_body_parser(CONF)
ok(matched_ids() == "request_body_parser_violation",
   "malformed JSON without the control: request_body_parser_violation", matched_ids())

-- 4c. content-type enforce (uninspectable body)
request("text/plain", "hello")
fresh(true)
engine:check_request_content_type_enforce(CONF)
ok(matched_ids() == "", "text/plain body under body_access_off: exempt from the CT gate", matched_ids())
fresh(false)
engine:check_request_content_type_enforce(CONF)
ok(matched_ids() == "check_request_content_type_enforce",
   "text/plain body without the control: check_request_content_type_enforce", matched_ids())

-- 4d. the switch-off rule itself resolves on the path with no body access
request("application/x-www-form-urlencoded", "a=1&b=2&c=3", "")
local rc = fresh(false)
local r_off_bw = parse_one(SEC_OFF_BW)
ka_compile.compile_rules({ r_off_bw }, nil)
ok(ka_compile.is_prebody_control(r_off_bw) == true, "@beginsWith variant is pre-body too")
local matched = engine:loop_rule_controls_pass({ paranoia_level = 1, engine_fast_path = true }, { r_off_bw }, "access")
ok(#matched == 1 and matched[1].id == "10001011", "pre-body pass matches the shop rule on the path", #matched)
ok(kong.ctx.plugin.ka_raw_body == nil, "matching a path-only control never reads the body")
if matched[1] then engine.__apply_rule_controls_inline(matched[1].rule_control, matched[1].id) end
ok(rc.body_access_off == true, "its control lands in the store")
ok(engine:check_request_arg_count(CONF) == false and kong.ctx.plugin.ka_raw_body == nil,
   "then the arg-count gate lets 3 body args through a limit of 2, body still unread")

-- ============================================================
print("\n5. global pack: controls_prebody split after compile")
-- ============================================================
local gr = require("kong.plugins.karna.ka_global_rules")
local JSON_RULES = [=[[
  {"id":"g_off","phase":"access","conditions":[{"op":"beginsWith","value":"/upload","variables":["request.path"]}],"rule_control":[{"body_access_off":true}]},
  {"id":"g_args","phase":"access","conditions":[{"op":"rx","value":"x","variables":["request.arg.value"]}],"rule_control":[{"remove_rule":{"rule_id":"942100"}}]},
  {"id":"g_block","phase":"access","conditions":[{"op":"contains","value":"a","variables":["request.path"]}],"action":{"fixed_response":{"status_code":403}}},
  {"id":"g_resp","phase":"header_filter","conditions":[{"op":"contains","value":"b","variables":["response.header.value"]}],"rule_control":[{"remove_rule":{"rule_id":"950100"}}]}
]]=]

gr._compile = ka_compile.compile_rules
local pack, errs = gr.build_sources({ { name = "t", json = JSON_RULES, seclang = SEC_OFF .. "\n" .. SEC_ARGS } }, "1")
ok(pack ~= nil and #errs == 0, "pack builds", errs and errs[1])
ok(pack and ids(pack.controls_prebody.access) == "g_off,10001010",
   "pre-body controls: JSON path rule + SecLang REQUEST_URI rule", pack and ids(pack.controls_prebody.access))
ok(pack and ids(pack.controls.access) == "g_args,10001020",
   "ARGS controls stay in controls.access", pack and ids(pack.controls.access))
ok(pack and ids(pack.detection.access) == "g_block", "detection unchanged", pack and ids(pack.detection.access))
ok(pack and ids(pack.controls.header_filter) == "g_resp", "header_filter controls untouched")
ok(pack and pack.n_controls == 5 and pack.n_detection == 1,
   "counts: 5 controls (2 pre-body, 2 post-gate, 1 header_filter) + 1 detection",
   pack and (pack.n_controls .. "/" .. pack.n_detection))

gr._file_pack, gr._redis_pack = pack, nil
local combined = gr.recombine()
ok(ids(combined.controls_prebody.access) == "g_off,10001010", "recombine carries controls_prebody", ids(combined.controls_prebody.access))
ok(ids(combined.controls.access) == "g_args,10001020" and ids(combined.detection.access) == "g_block",
   "recombine keeps the other lists")
ok(#combined.all == 6, "all = 6 rules", #combined.all)

gr._compile = nil
local pack_nc = gr.build_sources({ { name = "t", json = JSON_RULES, seclang = "" } }, "2")
ok(pack_nc and #pack_nc.controls_prebody.access == 0 and ids(pack_nc.controls.access) == "g_off,g_args",
   "without a compiler nothing is pre-body: every control keeps its post-gate slot")
gr._file_pack, gr._redis_pack = nil, nil
gr.recombine()

-- ============================================================
print("\n6. handler.lua: custom_secrules and rules_request split (plugin._internals)")
-- ============================================================
for _, name in ipairs({ "ka_re2_gate", "ka_header_names", "ka_tls" }) do
    package.preload["kong.plugins.karna." .. name] = function() return {} end
end
package.preload["kong.plugins.karna.ka_redact"] = function() return dofile("./kong/plugins/karna/modules/ka_redact.lua") end
package.preload["kong.plugins.karna.version"] = function()
    return { version = "0.0.0-test", commit = "deadbee", commit_short = "deadbee", built_at = "test" }
end
kong.response.exit = kong.response.exit or function() end
kong.response.set_header = kong.response.set_header or function() end

local handler = dofile("./kong/plugins/karna/handler.lua")
local I = handler._internals
ok(I and I.get_plugin_dynamic_rules and I.get_local_request_rules, "handler._internals seam present")

local conf = {
    __plugin_id = "p1", __seq__ = 7, private_debug = false,
    custom_secrules = { SEC_OFF, SEC_ARGS, SEC_DENY, SEC_SETV },
    rules_request = {
        '{"id":"l_off","phase":"access","conditions":[{"op":"beginsWith","value":"/upload","variables":["request.path"]}],"rule_control":[{"body_access_off":true}]}',
        '{"id":"l_args","phase":"access","conditions":[{"op":"rx","value":"x","variables":["request.arg.value"]}],"rule_control":[{"remove_rule":{"rule_id":"942100"}}]}',
        '{"id":"l_block","phase":"access","conditions":[{"op":"contains","value":"a","variables":["request.path"]}],"action":{"fixed_response":{"status_code":403}}}',
        '{"id":"l_resp","phase":"header_filter","conditions":[{"op":"contains","value":"b","variables":["response.header.value"]}],"action":{"fixed_response":{"status_code":403}}}',
    },
}
local dyn = I.get_plugin_dynamic_rules(conf)
ok(dyn and ids(dyn.controls_prebody.access) == "10001010", "custom_secrules: the REQUEST_URI switch-off rule is pre-body", dyn and ids(dyn.controls_prebody.access))
ok(dyn and ids(dyn.controls.access) == "10001020", "custom_secrules: the ARGS control stays post-gate", dyn and ids(dyn.controls.access))
ok(dyn and ids(dyn.detection.access) == "10001030,10001040", "custom_secrules: deny + setvar rules are detection", dyn and ids(dyn.detection.access))
ok(dyn and #dyn.all == 4, "all four parsed")

local loc = I.get_local_request_rules(conf)
ok(loc and ids(loc.access_prebody) == "l_off", "rules_request: path-keyed body_access_off is pre-body", loc and ids(loc.access_prebody))
ok(loc and ids(loc.access) == "l_args,l_block", "rules_request: .access is the remainder (each rule runs once)", loc and ids(loc.access))
ok(loc and ids(loc.header_filter) == "l_resp" and #loc.all == 4, "rules_request: other views unchanged")

local empty = I.get_local_request_rules({ __plugin_id = "p2", __seq__ = 1 })
ok(empty and type(empty.access_prebody) == "table" and #empty.access_prebody == 0, "no rules_request → empty access_prebody list")

-- ============================================================
print("")
if fails == 0 then print("ALL PASS") else print(fails .. " test(s) failed"); os.exit(1) end
