-- ka-unittest/conf_cache_key.lua
--
-- handler.lua keeps three compiled views of a plugin instance's configuration
-- in the worker-local `ka_rules` LRU (10000 entries, no TTL): the parsed
-- `rules_request` (get_local_request_rules), the parsed `custom_secrules` and
-- CRS exclusion plugins (get_plugin_dynamic_rules), and the two override arrays
-- (get_overrides_cached). Up to 1.5.4 the cache key was the config table's
-- address, `tostring(plugin_conf)`, on the assumption that an Admin API write
-- hands the plugin a new table and so "invalidates" the entry. It does not: the
-- old entry is never removed, and once the old table is garbage-collected
-- LuaJIT can give the same address to the config table of a DIFFERENT plugin
-- instance, which then hits the stale entry and evaluates another service's
-- compiled rules (seen as 403s carrying a foreign rule id, right after Admin
-- API writes, on services whose own rules_request is non-empty).
--
-- The key is now conf_cache_key(prefix, conf) = "<prefix>:<__plugin_id>:<__seq__>".
-- Kong's plugins iterator stamps both fields on every new config table;
-- `__seq__` is a shared-dict counter, so it is fresh on every reconfiguration
-- and unique across workers. No `__seq__`, or `__seq__ == 0` (Kong's own
-- incr-failed sentinel), means no safe identity: the getters then build the
-- value fresh and never write to the cache.
--
-- This test loads the REAL handler.lua behind stubbed Kong modules and drives
-- the getters through the `plugin._internals` seam, so it pins the actual
-- keying rather than a mirror of it.
--
-- Run from repo root:
--   lua ka-unittest/conf_cache_key.lua

local fails = 0
local function ok(cond, name)
    if cond then
        print("  ok   - " .. name)
    else
        fails = fails + 1
        print("  FAIL - " .. name)
    end
end

-- ---------------------------------------------------------------------------
-- stubs
-- ---------------------------------------------------------------------------

-- resty.lrucache: the subset handler.lua uses, plus write accounting so a test
-- can assert "nothing was cached".
local CACHE
package.preload["resty.lrucache"] = function()
    return {
        new = function(size)
            local store, writes = {}, {}
            CACHE = {
                size = size,
                get = function(_, k) return store[k] end,
                set = function(_, k, v) store[k] = v; writes[#writes + 1] = k end,
                delete = function(_, k) store[k] = nil end,
                flush_all = function(_) store = {} end,
                writes = function() return writes end,
            }
            return CACHE
        end,
    }
end

-- cjson: rules_request / override entries are JSON strings in the config. The
-- decoder is a fixture lookup (string -> fresh copy of the table), so the test
-- needs no JSON parser and an unknown string is loud instead of silently empty.
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

-- ka_compile: record which plugin instance each compile ran for, and tag the
-- rules, so "B got A's compiled rules" is observable on the returned tables.
local COMPILES = {}
package.preload["kong.plugins.karna.ka_compile"] = function()
    return {
        compile_rules = function(rules, plugin_conf)
            COMPILES[#COMPILES + 1] = tostring(plugin_conf.__plugin_id)
            for _, r in ipairs(rules) do r.compiled_for = tostring(plugin_conf.__plugin_id) end
        end,
        is_control_only = function(rule)
            if type(rule.rule_control) ~= "table" then return false end
            local action = rule.action
            if action == nil then return true end
            return type(action) == "table" and next(action) == nil
        end,
    }
end

-- seclang: one detection rule per inline SecLang string, id taken from it.
package.preload["kong.plugins.karna.ka_seclang"] = function()
    return {
        collect_plugin_conf_files = function() return {} end,
        parse_isolated = function(raw)
            local id = raw:match("id:(%d+)") or raw
            return { { id = id, phase = "access", action = { fixed_response = { status_code = 403 } } } }
        end,
    }
end

for _, name in ipairs({ "ka_engine", "ka_body_parser", "ka_utils", "ka_mcp",
                        "ka_global_rules", "ka_re2_gate", "ka_header_names", "ka_tls" }) do
    package.preload["kong.plugins.karna." .. name] = function() return {} end
end
package.preload["kong.plugins.karna.version"] = function()
    return { version = "0.0.0-test", commit = "deadbee", commit_short = "deadbee", built_at = "test" }
end
package.preload["resty.ipmatcher"] = function() return {} end

local ERRORS = {}
_G.ngx = { worker = { id = function() return 0 end } }
_G.kong = {
    log = {
        debug  = function() end,
        warn   = function() end,
        notice = function() end,
        err    = function(...) ERRORS[#ERRORS + 1] = table.concat({ ... }, "") end,
    },
    response = { exit = function() end, set_header = function() end },
    ctx = { plugin = {}, shared = {} },
}

local handler = dofile("./kong/plugins/karna/handler.lua")
local I = handler._internals
assert(I and I.conf_cache_key and I.get_plugin_dynamic_rules
       and I.get_local_request_rules and I.get_overrides_cached,
       "handler._internals seam missing")

-- ---------------------------------------------------------------------------
-- fixtures
-- ---------------------------------------------------------------------------
local RULE_A = fixture(
    '{"id":"svc_a_block","phase":"access","action":{"fixed_response":{"status_code":403}}}',
    { id = "svc_a_block", phase = "access", action = { fixed_response = { status_code = 403 } } })
local RULE_A2 = fixture(
    '{"id":"svc_a_v2_block","phase":"access","action":{"fixed_response":{"status_code":403}}}',
    { id = "svc_a_v2_block", phase = "access", action = { fixed_response = { status_code = 403 } } })
local RULE_B = fixture(
    '{"id":"svc_b_block","phase":"access","action":{"fixed_response":{"status_code":403}}}',
    { id = "svc_b_block", phase = "access", action = { fixed_response = { status_code = 403 } } })
local RULE_B_HF = fixture(
    '{"id":"svc_b_hdr","phase":"header_filter","action":{"fixed_response":{"status_code":403}}}',
    { id = "svc_b_hdr", phase = "header_filter", action = { fixed_response = { status_code = 403 } } })
local OVR_A = fixture(
    '{"selector":{"tags":["attack-xss"]},"action":{"type":"fix"}}',
    { selector = { tags = { "attack-xss" } }, action = { type = "fix" } })
local OVR_B = fixture(
    '{"selector":{"ids":["svc_b_block"]},"action":{"type":"passthrough"}}',
    { selector = { ids = { "svc_b_block" } }, action = { type = "passthrough" } })
local RESP_B = fixture(
    '{"selector":{"any":true},"response":{"status_code":418}}',
    { selector = { any = true }, response = { status_code = 418 } })
local SEC_A = 'SecRule ARGS "@rx a" "id:100001,phase:2,deny"'
local SEC_A2 = 'SecRule ARGS "@rx a2" "id:100003,phase:2,deny"'
local SEC_B = 'SecRule ARGS "@rx b" "id:100002,phase:2,deny"'

-- a config table as Kong's plugins iterator hands it to the plugin
local function conf(plugin_id, seq, fields)
    local c = { __plugin_id = plugin_id, __seq__ = seq }
    for k, v in pairs(fields or {}) do c[k] = v end
    return c
end

local function writes() return #CACHE.writes() end
local function keys_contain(needle)
    for _, k in ipairs(CACHE.writes()) do
        if k:find(needle, 1, true) then return true end
    end
    return false
end
local function distinct(list)
    local seen = {}
    for _, k in ipairs(list) do
        if seen[k] then return false end
        seen[k] = true
    end
    return true
end

-- ---------------------------------------------------------------------------
print("\n- conf_cache_key: identity is plugin id + __seq__, never the address")
-- ---------------------------------------------------------------------------
local c1 = conf("plugin-1", 7)
ok(I.conf_cache_key("p", c1) == "p:plugin-1:7", "format is <prefix>:<__plugin_id>:<__seq__>")
ok(I.conf_cache_key("p", conf("plugin-1", 8)) ~= I.conf_cache_key("p", c1),
   "same plugin, new __seq__ → different key")
ok(I.conf_cache_key("p", conf("plugin-2", 7)) ~= I.conf_cache_key("p", c1),
   "different plugin, same __seq__ → different key")
ok(I.conf_cache_key("p", c1) ~= I.conf_cache_key("q", c1), "prefix is part of the key")
ok(not I.conf_cache_key("p", c1):find(tostring(c1), 1, true), "the table address is not in the key")
ok(I.conf_cache_key("p", conf("plugin-1", nil)) == nil, "__seq__ missing → nil (no safe identity)")
ok(I.conf_cache_key("p", conf("plugin-1", 0)) == nil, "__seq__ == 0 (Kong incr-failed sentinel) → nil")
ok(I.conf_cache_key("p", conf(nil, 7)) == "p:nil:7",
   "__plugin_id missing but __seq__ present → still a key (__seq__ alone is unique)")

-- ---------------------------------------------------------------------------
print("\n- two plugin instances: each getter returns its own rules")
-- ---------------------------------------------------------------------------
local A = conf("plugin-a", 1, {
    rules_request = { RULE_A },
    custom_secrules = { SEC_A },
    rule_action_overrides = { OVR_A },
})
local B = conf("plugin-b", 2, {
    rules_request = { RULE_B, RULE_B_HF },
    custom_secrules = { SEC_B },
    rule_action_overrides = { OVR_B },
    rule_response_overrides = { RESP_B },
})

local la, lb = I.get_local_request_rules(A), I.get_local_request_rules(B)
ok(#la.all == 1 and la.all[1].id == "svc_a_block", "A rules_request → A's rule")
ok(#la.access == 1 and #la.header_filter == 0, "A per-phase views")
ok(#lb.all == 2 and lb.all[1].id == "svc_b_block" and lb.all[2].id == "svc_b_hdr",
   "B rules_request → B's rules")
ok(#lb.access == 1 and lb.access[1].id == "svc_b_block"
   and #lb.header_filter == 1 and lb.header_filter[1].id == "svc_b_hdr",
   "B per-phase views")
ok(la.all[1].compiled_for == "plugin-a" and lb.all[1].compiled_for == "plugin-b",
   "each set compiled with its own plugin_conf")

local da, db = I.get_plugin_dynamic_rules(A), I.get_plugin_dynamic_rules(B)
ok(#da.detection.access == 1 and da.detection.access[1].id == "100001",
   "A custom_secrules → A's SecLang rule")
ok(#db.detection.access == 1 and db.detection.access[1].id == "100002",
   "B custom_secrules → B's SecLang rule")
ok(#da.controls.access == 0 and #db.controls.access == 0, "no controls in either")

local oa, ob = I.get_overrides_cached(A), I.get_overrides_cached(B)
ok(#oa.action_overrides == 1 and oa.action_overrides[1].selector.tags[1] == "attack-xss"
   and #oa.response_overrides == 0, "A overrides → A's action override only")
ok(#ob.action_overrides == 1 and ob.action_overrides[1].selector.ids[1] == "svc_b_block"
   and #ob.response_overrides == 1 and ob.response_overrides[1].response.status_code == 418,
   "B overrides → B's action + response overrides")

ok(writes() == 6 and distinct(CACHE.writes()), "six cache entries, all under distinct keys")
ok(keys_contain("plugin-a") and keys_contain("plugin-b"), "keys carry the plugin id")
ok(keys_contain(":1") and keys_contain(":2"), "keys carry __seq__")
ok(not keys_contain("table:"), "no key carries a table address")

local compiles_before = #COMPILES
ok(rawequal(I.get_local_request_rules(A), la) and rawequal(I.get_plugin_dynamic_rules(A), da)
   and rawequal(I.get_overrides_cached(A), oa), "second call on the same conf is a cache hit")
ok(#COMPILES == compiles_before, "cache hit → no recompile")
ok(rawequal(I.get_local_request_rules(B), lb), "B's hit is B's entry")

-- ---------------------------------------------------------------------------
print("\n- reconfiguration: same plugin id, higher __seq__, new rules")
-- ---------------------------------------------------------------------------
local A2 = conf("plugin-a", 3, { rules_request = { RULE_A2 }, custom_secrules = { SEC_A2 } })
compiles_before = #COMPILES
local la2 = I.get_local_request_rules(A2)
ok(not rawequal(la2, la), "new conf table does not get the previous compiled set")
ok(#la2.all == 1 and la2.all[1].id == "svc_a_v2_block", "new conf → its own rules_request")
local da2 = I.get_plugin_dynamic_rules(A2)
ok(not rawequal(da2, da) and da2.detection.access[1].id == "100003",
   "new conf → its own custom_secrules")
local oa2 = I.get_overrides_cached(A2)
ok(not rawequal(oa2, oa) and #oa2.action_overrides == 0,
   "new conf without overrides → empty overrides, not the previous ones")
ok(#COMPILES == compiles_before + 2, "reconfiguration recompiles (rules_request + dynamic)")
ok(rawequal(I.get_local_request_rules(A), la), "the previous conf table keeps its own entry")

-- ---------------------------------------------------------------------------
print("\n- address reuse: B's config table prints as A's did")
-- ---------------------------------------------------------------------------
-- LuaJIT can hand the address of a collected table to a new one. Simulated
-- with a __tostring that makes both tables print the same, which is exactly
-- what the old `"prefix:" .. tostring(plugin_conf)` key saw.
local SAME = "table: 0x7f00deadbeef"
local same_mt = { __tostring = function() return SAME end }
local RA = setmetatable(conf("plugin-a", 20, {
    rules_request = { RULE_A }, custom_secrules = { SEC_A }, rule_action_overrides = { OVR_A },
}), same_mt)
local ra_l, ra_d, ra_o = I.get_local_request_rules(RA), I.get_plugin_dynamic_rules(RA), I.get_overrides_cached(RA)
RA = nil
collectgarbage(); collectgarbage()
local RB = setmetatable(conf("plugin-b", 21, {
    rules_request = { RULE_B }, custom_secrules = { SEC_B }, rule_response_overrides = { RESP_B },
}), same_mt)
ok(tostring(RB) == SAME, "harness: B's table prints exactly as A's did")

local rb_l = I.get_local_request_rules(RB)
ok(not rawequal(rb_l, ra_l), "rules_request: B does not get A's cached entry")
ok(#rb_l.all == 1 and rb_l.all[1].id == "svc_b_block" and rb_l.all[1].compiled_for == "plugin-b",
   "rules_request: B evaluates its own rule, compiled for B")
local rb_d = I.get_plugin_dynamic_rules(RB)
ok(not rawequal(rb_d, ra_d) and rb_d.detection.access[1].id == "100002",
   "custom_secrules: B gets its own SecLang rule, not A's")
local rb_o = I.get_overrides_cached(RB)
ok(not rawequal(rb_o, ra_o) and #rb_o.action_overrides == 0 and #rb_o.response_overrides == 1,
   "overrides: B gets its own overrides, not A's action override")
ok(not keys_contain(SAME), "no cache key ever contained the shared address string")

-- ---------------------------------------------------------------------------
print("\n- __seq__ missing or 0: correct values, nothing written to the cache")
-- ---------------------------------------------------------------------------
for _, case in ipairs({ { label = "missing", seq = nil }, { label = "zero", seq = 0 } }) do
    local C = conf("plugin-c-" .. case.label, case.seq, {
        rules_request = { RULE_B, RULE_B_HF }, custom_secrules = { SEC_B },
        rule_action_overrides = { OVR_B }, rule_response_overrides = { RESP_B },
    })
    local before_w, before_c = writes(), #COMPILES
    local l1 = I.get_local_request_rules(C)
    ok(#l1.all == 2 and l1.access[1].id == "svc_b_block" and l1.header_filter[1].id == "svc_b_hdr",
       "__seq__ " .. case.label .. ": rules_request parsed correctly")
    local d1 = I.get_plugin_dynamic_rules(C)
    ok(d1.detection.access[1].id == "100002", "__seq__ " .. case.label .. ": custom_secrules parsed correctly")
    local o1 = I.get_overrides_cached(C)
    ok(#o1.action_overrides == 1 and #o1.response_overrides == 1,
       "__seq__ " .. case.label .. ": overrides parsed correctly")
    ok(writes() == before_w, "__seq__ " .. case.label .. ": no cache write")
    local l2 = I.get_local_request_rules(C)
    ok(not rawequal(l2, l1) and l2.all[1].id == "svc_b_block",
       "__seq__ " .. case.label .. ": second call builds fresh (uncached), same content")
    ok(#COMPILES == before_c + 3, "__seq__ " .. case.label .. ": every call compiles: rules_request twice + dynamic once, none cached")
end

-- ---------------------------------------------------------------------------
print("\n- empty inputs keep their early return (never touch the cache)")
-- ---------------------------------------------------------------------------
local before_w = writes()
local e = I.get_local_request_rules(conf("plugin-e", 30, {}))
ok(#e.all == 0 and #e.access == 0 and #e.header_filter == 0, "no rules_request → empty views")
ok(writes() == before_w, "no rules_request → no cache write")
ok(#ERRORS == 0, "no parse errors were logged along the way")

-- ---------------------------------------------------------------------------
print("\n- rate_limit_scope: the counter key is namespaced by plugin instance")
-- ---------------------------------------------------------------------------
-- Two services can carry a rule with the same id (a copied rule, a rule shipped
-- by the global pack) and the same `key` macro. Without a namespace in the
-- Redis key they share one counter, so traffic to one service throttles clients
-- of the other. The scope is the plugin entity id and NOT `__seq__`: unlike the
-- cache key above, a counter must survive a configuration edit rather than
-- reset on every Admin API write.
ok(type(I.rate_limit_scope) == "function", "rate_limit_scope is exposed on the seam")

ok(I.rate_limit_scope({ __plugin_id = "plugin-a", __seq__ = 7 }) == "plugin-a",
   "the plugin entity id is the scope")
ok(I.rate_limit_scope({ __plugin_id = "plugin-a", __seq__ = 7 })
   == I.rate_limit_scope({ __plugin_id = "plugin-a", __seq__ = 8 }),
   "a configuration edit (new __seq__) does NOT move the counter")
ok(I.rate_limit_scope({ __plugin_id = "plugin-a" })
   ~= I.rate_limit_scope({ __plugin_id = "plugin-b" }),
   "two plugin instances never share a counter")

-- No plugin id: fall back to the service, then to a constant. A key is always
-- well-formed — a nil in the middle of the concatenation would throw in the
-- access phase, on a request that was merely being counted.
ok(I.rate_limit_scope({}) ~= nil and I.rate_limit_scope({}) ~= "",
   "no __plugin_id → still a usable scope (service id, else a constant)")
ok(I.rate_limit_scope({ __plugin_id = "" }) ~= "", "an empty id is not a scope")
ok(I.rate_limit_scope(nil) ~= nil, "nil config → still a usable scope")

print(string.format("\n%d test(s) failed", fails))
os.exit(fails == 0 and 0 or 1)
