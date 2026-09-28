-- ka-unittest/header_filter_cache_hit.lua
--
-- A sibling plugin that serves a response from its cache exits in the access
-- phase before Karna runs and sets `kong.ctx.shared.response_from_cache`. Kong
-- still runs Karna's header_filter for that request. Up to 1.6.0 the phase
-- returned at once on the flag, so a local rule with `phase: "header_filter"`
-- never saw a cached response: a per-client counter kept by such a rule (an
-- asset counter keyed on a request header, say) missed every cached asset and
-- never reached its threshold, while the audit log showed those requests as
-- served. The phase now evaluates the local response-phase rules on a cache
-- hit, on a request context it creates itself (access never ran), and skips
-- everything else exactly as before.
--
-- Pinned here, on the REAL handler.lua behind stubbed Kong modules:
--   1. cache hit + local header_filter rules: the header_filter subset is
--      evaluated once, in the header_filter phase, after the scratch tables,
--      the rule-control store, the TLS block and the inspection table exist;
--      the Karna response headers are still not set;
--   2. cache hit + no local header_filter rule: nothing runs and the request
--      context stays untouched (zero cost for every other service);
--   3. cache hit + local rules disabled: same;
--   4. a terminal header_filter rule on a cache hit blocks without throwing —
--      the match is recorded on a scratch table that did not exist before;
--   5. access already ran (a cache below Karna in the plugin chain): its
--      tables are kept, not replaced;
--   6. no cache hit: the response-phase rules are evaluated exactly once, so
--      the new branch does not double-evaluate on a miss.
--
-- Fixtures are synthetic.
--
-- Run from repo root:
--   lua ka-unittest/header_filter_cache_hit.lua

local fails = 0
local function ok(cond, name, detail)
    if cond then
        print("  ok   - " .. name)
    else
        fails = fails + 1
        print("  FAIL - " .. name .. (detail and ("  (" .. tostring(detail) .. ")") or ""))
    end
end

-- ---------------------------------------------------------------------------
-- stubs
-- ---------------------------------------------------------------------------

package.preload["resty.lrucache"] = function()
    return {
        new = function()
            local store = {}
            return {
                get = function(_, k) return store[k] end,
                set = function(_, k, v) store[k] = v end,
                delete = function(_, k) store[k] = nil end,
                flush_all = function(_) store = {} end,
            }
        end,
    }
end

-- cjson: rules_request entries are JSON strings in the config. The decoder is
-- a fixture lookup (string -> fresh copy of the table).
local FIXTURES = {}
local function deep_copy(v)
    if type(v) ~= "table" then return v end
    local out = {}
    for k, x in pairs(v) do out[k] = deep_copy(x) end
    return out
end
local function fixture(json, tbl) FIXTURES[json] = tbl; return json end
package.preload["cjson"] = function()
    return {
        decode = function(s)
            local t = FIXTURES[s]
            if t == nil then error("unknown fixture: " .. tostring(s)) end
            return deep_copy(t)
        end,
        encode = function() return "" end,
        empty_array = setmetatable({}, {}),
    }
end

package.preload["kong.plugins.karna.ka_compile"] = function()
    return {
        compile_rules = function() end,
        is_control_only = function() return false end,
        is_prebody_control = function() return false end,
    }
end
package.preload["kong.plugins.karna.ka_seclang"] = function()
    return {
        collect_plugin_conf_files = function() return {} end,
        parse_isolated = function() return {} end,
    }
end

-- The engine: what the handler asks of it in header_filter, recorded.
local LOOPS, INSPECTIONS = {}, 0
local ENGINE = {}
function ENGINE.loop_rules(_, _, rules, phase)
    local ctx = kong.ctx.plugin
    LOOPS[#LOOPS + 1] = {
        phase = phase,
        ids = (function()
            local ids = {}
            for _, r in ipairs(rules) do ids[#ids + 1] = r.id end
            return table.concat(ids, ",")
        end)(),
        -- the request context the rules would run against
        scratch_ok = type(ctx.ka_matched_rules) == "table"
                     and type(ctx.ka_value_cache) == "table"
                     and type(ctx.ka_variable_cache) == "table"
                     and type(ctx.rule_variables) == "table",
        controls_ok = type(ctx.rule_controls) == "table"
                      and ctx.rule_controls.engine_off == false
                      and type(ctx.rule_controls.ids) == "table",
        inspection_ok = type(ctx.inspection_table) == "table",
        tls_ok = ctx.tls ~= nil,
    }
    -- a terminal rule matches; a non-terminal one only fires its side effects
    for _, r in ipairs(rules) do
        if r.action and r.action.fixed_response then return true, r, {} end
    end
end
function ENGINE.get_inspection_table(_, _)
    INSPECTIONS = INSPECTIONS + 1
    kong.ctx.plugin.inspection_table = kong.ctx.plugin.inspection_table or {}
end
function ENGINE.get_redis_conf() return {} end
package.preload["kong.plugins.karna.ka_engine"] = function() return ENGINE end

-- ka_tls.populate is what makes tls.* resolvable; access calls it, and on a
-- cache hit nobody else does.
local TLS_POPULATED = 0
package.preload["kong.plugins.karna.ka_tls"] = function()
    return {
        populate = function()
            TLS_POPULATED = TLS_POPULATED + 1
            kong.ctx.plugin.tls = { enabled = true, capture_status = "complete" }
        end,
    }
end

package.preload["kong.plugins.karna.ka_utils"] = function()
    return {
        build_block_response = function(_, _, body, headers, fallback)
            return body or fallback, headers or {}
        end,
    }
end

for _, name in ipairs({ "ka_body_parser", "ka_mcp", "ka_global_rules", "ka_re2_gate",
                        "ka_header_names", "ka_redact" }) do
    package.preload["kong.plugins.karna." .. name] = function() return { get = function() end } end
end
package.preload["kong.plugins.karna.version"] = function()
    return { version = "0.0.0-test", commit = "deadbee", commit_short = "deadbee", built_at = "test" }
end
package.preload["resty.ipmatcher"] = function() return { new = function() return { match = function() end } end } end

local HEADERS, EXIT = {}, nil
_G.ngx = {
    worker = { id = function() return 0 end },
    var    = { remote_addr = "203.0.113.5" },
    timer  = { at = function() return true end },
}
_G.kong = {
    log = {
        debug = function() end, warn = function() end, notice = function() end,
        err = function() end, inspect = function() end,
    },
    request = {
        get_path = function() return "/asset.js" end,
        get_header = function() return nil end,
        get_method = function() return "GET" end,
        get_host = function() return "example.test" end,
        get_scheme = function() return "https" end,
    },
    response = {
        exit = function(status, body, headers)
            EXIT = { status = status, body = body, headers = headers }
            error("__EXIT__", 0)
        end,
        set_header = function(name, value) HEADERS[name] = value end,
    },
    ctx = { plugin = {}, shared = {} },
}

local handler = dofile("./kong/plugins/karna/handler.lua")

-- ---------------------------------------------------------------------------
-- fixtures
-- ---------------------------------------------------------------------------
local ACCESS_RULE = fixture(
    '{"id":"acc_block","phase":"access","action":{"fixed_response":{"status_code":403}}}',
    { id = "acc_block", phase = "access", action = { fixed_response = { status_code = 403 } } })
local HF_COUNT = fixture(
    '{"id":"hf_count","phase":"header_filter","log":false,"action":{"redis_incr_key":{"key":"cnt:%{remote_addr}","expire":900}}}',
    { id = "hf_count", phase = "header_filter", log = false,
      action = { redis_incr_key = { key = "cnt:%{remote_addr}", expire = 900 } } })
local HF_MARK = fixture(
    '{"id":"hf_mark","phase":"header_filter","log":false,"action":{"redis_set":{"key":"seen:%{remote_addr}","value":"1","expire":900}}}',
    { id = "hf_mark", phase = "header_filter", log = false,
      action = { redis_set = { key = "seen:%{remote_addr}", value = "1", expire = 900 } } })
local HF_BLOCK = fixture(
    '{"id":"hf_block","phase":"header_filter","action":{"fixed_response":{"status_code":403}}}',
    { id = "hf_block", phase = "header_filter", action = { fixed_response = { status_code = 403 } } })

local seq = 0
local function conf(fields)
    seq = seq + 1
    local c = { __plugin_id = "plugin-a", __seq__ = seq, local_rules_enabled = true,
                engine_blocking_mode = true, set_karna_headers = true }
    for k, v in pairs(fields or {}) do c[k] = v end
    return c
end

local function run(plugin_conf, cache_hit, plugin_ctx)
    LOOPS, INSPECTIONS, TLS_POPULATED, HEADERS, EXIT = {}, 0, 0, {}, nil
    kong.ctx.plugin = plugin_ctx or {}
    kong.ctx.shared = { response_from_cache = cache_hit }
    local called_ok, err = pcall(handler.header_filter, handler, plugin_conf)
    if not called_ok and tostring(err) ~= "__EXIT__" then
        return false, err
    end
    return true
end

-- ---------------------------------------------------------------------------
print("\n- cache hit: the local header_filter rules are evaluated")
-- ---------------------------------------------------------------------------
local c1 = conf({ rules_request = { ACCESS_RULE, HF_COUNT, HF_MARK } })
local r_ok, r_err = run(c1, true)
ok(r_ok, "header_filter does not throw on a cache hit", r_err)
ok(#LOOPS == 1, "the rules are evaluated once", "loops=" .. #LOOPS)
ok(LOOPS[1] and LOOPS[1].phase == "header_filter", "in the header_filter phase")
ok(LOOPS[1] and LOOPS[1].ids == "hf_count,hf_mark",
   "only the header_filter subset, the access rule is not evaluated", LOOPS[1] and LOOPS[1].ids)
ok(LOOPS[1] and LOOPS[1].scratch_ok, "the scratch tables exist when the rules run")
ok(LOOPS[1] and LOOPS[1].controls_ok, "the rule-control store exists, with nothing switched off")
ok(LOOPS[1] and LOOPS[1].tls_ok and TLS_POPULATED == 1, "tls.* is populated before the rules run")
ok(LOOPS[1] and LOOPS[1].inspection_ok and INSPECTIONS == 1, "the inspection table is built before the rules run")
ok(next(HEADERS) == nil, "the Karna response headers are still not set on a cached response")
ok(EXIT == nil, "a non-terminal rule does not terminate the response")
ok(#kong.ctx.plugin.ka_matched_rules == 0, "no match recorded for non-terminal rules")

-- ---------------------------------------------------------------------------
print("\n- cache hit: nothing to evaluate → nothing runs, context untouched")
-- ---------------------------------------------------------------------------
local c2 = conf({ rules_request = { ACCESS_RULE } })
r_ok, r_err = run(c2, true)
ok(r_ok, "no throw", r_err)
ok(#LOOPS == 0, "no rule loop for a service with access rules only")
ok(INSPECTIONS == 0 and TLS_POPULATED == 0, "no inspection table, no TLS capture")
ok(kong.ctx.plugin.ka_matched_rules == nil and kong.ctx.plugin.rule_controls == nil,
   "the request context is left empty, as before")
ok(next(HEADERS) == nil, "no headers set")

local c3 = conf({ rules_request = {} })
r_ok = run(c3, true)
ok(r_ok and #LOOPS == 0 and INSPECTIONS == 0, "an empty rules_request runs nothing")

local c4 = conf({ rules_request = { HF_COUNT }, local_rules_enabled = false })
r_ok = run(c4, true)
ok(r_ok and #LOOPS == 0 and INSPECTIONS == 0, "local rules disabled → nothing runs")
ok(kong.ctx.plugin.ka_matched_rules == nil, "and the context stays empty")

-- ---------------------------------------------------------------------------
print("\n- cache hit: a terminal header_filter rule blocks without throwing")
-- ---------------------------------------------------------------------------
local c5 = conf({ rules_request = { HF_BLOCK } })
r_ok, r_err = run(c5, true)
ok(r_ok, "no error from the phase (the match table exists)", r_err)
ok(EXIT and EXIT.status == 403, "the rule's fixed_response is served", EXIT and EXIT.status)
ok(kong.ctx.plugin.ka_matched_rules and #kong.ctx.plugin.ka_matched_rules == 1
   and kong.ctx.plugin.ka_matched_rules[1].rule.id == "hf_block",
   "the match is recorded for the audit log")
ok(kong.ctx.plugin.ka_matched_rules[1].blocked == true, "and marked as blocked")

-- ---------------------------------------------------------------------------
print("\n- cache hit after access already ran: its tables are kept")
-- ---------------------------------------------------------------------------
local existing_matches = { { rule = { id = "from_access" } } }
local existing_controls = { engine_off = false, ids = {}, marker = "from_access" }
local existing_values = {}
local c6 = conf({ rules_request = { HF_COUNT } })
r_ok, r_err = run(c6, true, {
    ka_matched_rules = existing_matches, rule_controls = existing_controls,
    ka_value_cache = existing_values, ka_variable_cache = {}, rule_variables = {},
    tls = { enabled = false, capture_status = "not_tls" },
})
ok(r_ok, "no throw", r_err)
ok(#LOOPS == 1 and LOOPS[1].ids == "hf_count", "the rules are evaluated")
ok(rawequal(kong.ctx.plugin.ka_matched_rules, existing_matches),
   "the matched-rules table from access is kept (identity)")
ok(rawequal(kong.ctx.plugin.rule_controls, existing_controls)
   and kong.ctx.plugin.rule_controls.marker == "from_access",
   "the rule-control store from access is kept, with its state")
ok(rawequal(kong.ctx.plugin.ka_value_cache, existing_values), "the value cache from access is kept")
ok(#kong.ctx.plugin.ka_matched_rules == 1, "nothing was appended for the non-terminal rule")

-- ---------------------------------------------------------------------------
print("\n- no cache hit: the response-phase rules run exactly once")
-- ---------------------------------------------------------------------------
local c7 = conf({ rules_request = { ACCESS_RULE, HF_COUNT } })
r_ok, r_err = run(c7, nil, {
    ka_matched_rules = {}, rule_controls = { engine_off = false, ids = {} },
    ka_value_cache = {}, ka_variable_cache = {}, rule_variables = {},
    tls = { enabled = true, capture_status = "complete" },
})
ok(r_ok, "no throw on the normal path", r_err)
ok(#LOOPS == 1 and LOOPS[1].ids == "hf_count" and LOOPS[1].phase == "header_filter",
   "the header_filter subset is evaluated once (no double evaluation)", LOOPS[1] and LOOPS[1].ids)
ok(HEADERS["X-Karna-Engine"] == "Karna", "the Karna headers are set on a proxied response")
ok(INSPECTIONS == 1, "the inspection table is built once")

r_ok = run(c7, false, { ka_matched_rules = {}, rule_controls = { engine_off = false, ids = {} },
                        ka_value_cache = {}, ka_variable_cache = {}, rule_variables = {} })
ok(r_ok and #LOOPS == 1, "response_from_cache = false behaves like absent")

print(string.format("\n%d test(s) failed", fails))
os.exit(fails == 0 and 0 or 1)
