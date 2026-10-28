-- ka-unittest/conf_cache_key.lua
--
-- handler.lua keeps compiled views of a plugin instance's configuration
-- in the worker-local `conf_cache` LRU (no TTL), among them the parsed
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
-- The key became conf_cache_key(prefix, conf) = "<prefix>:<__plugin_id>:<__seq__>".
-- Kong's plugins iterator stamps both fields on every new config table;
-- `__seq__` is a shared-dict counter, so it is fresh on every reconfiguration
-- and unique across workers. No `__seq__`, or `__seq__ == 0` (Kong's own
-- incr-failed sentinel), means no safe identity: the getters then build the
-- value fresh and never write to the cache.
--
-- The key alone left every superseded generation in the LRU: Kong rebuilds its
-- plugins iterator after any plugin write, every instance arrives with a new
-- `__seq__`, and the old entries waited for capacity eviction, so worker memory
-- grew with the number of reconfigurations. One generation per `__plugin_id` is
-- now kept, and the CRS pack sits in module locals where no eviction can reach
-- it. The `__seq__` in the key is replaced by a hash of the whole configuration
-- (except `__seq__`), so a rebuild that changed nothing for an instance reuses
-- its compiled sets; the schema-walk section checks that every field of
-- schema.lua is part of that hash.
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
-- can assert "nothing was cached", a live-entry count, and eviction of the
-- least recently written entry past `size` (enough to saturate it).
local CACHE
package.preload["resty.lrucache"] = function()
    return {
        new = function(size)
            local store, writes, order = {}, {}, {}
            local live = 0
            local function evict()
                while live > size do
                    local k = table.remove(order, 1)
                    if store[k] ~= nil then store[k] = nil; live = live - 1 end
                end
            end
            CACHE = {
                size = size,
                get = function(_, k) return store[k] end,
                set = function(_, k, v)
                    if store[k] == nil then live = live + 1 end
                    for i = #order, 1, -1 do
                        if order[i] == k then table.remove(order, i) end
                    end
                    store[k] = v; order[#order + 1] = k; writes[#writes + 1] = k
                    evict()
                end,
                delete = function(_, k)
                    if store[k] ~= nil then store[k] = nil; live = live - 1 end
                end,
                flush_all = function(_) store, order, live = {}, {}, 0 end,
                writes = function() return writes end,
                count = function() return live end,
                has = function(_, k) return store[k] ~= nil end,
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
        -- The pre-body split is pinned by prebody_controls.lua against the real
        -- compiler; here nothing is pre-body so every control keeps its slot.
        is_prebody_control = function() return false end,
    }
end

-- seclang: one detection rule per inline SecLang string, id taken from it.
-- CRS exclusion plugin files come from DISK[dir] (dir -> { fname = content }).
DISK = {}
package.preload["kong.plugins.karna.ka_seclang"] = function()
    return {
        collect_plugin_conf_files = function(dir) return deep_copy(DISK[dir] or {}) end,
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
-- ka_redact is pure Lua with no kong/ngx globals, so the cache test runs
-- against the real compiler rather than a stub.
package.preload["kong.plugins.karna.ka_redact"] = function()
    return dofile("./kong/plugins/karna/modules/ka_redact.lua")
end
package.preload["kong.plugins.karna.ka_arg_limits"] = function() return dofile("./kong/plugins/karna/modules/ka_arg_limits.lua") end
package.preload["kong.plugins.karna.version"] = function()
    return { version = "0.0.0-test", commit = "deadbee", commit_short = "deadbee", built_at = "test" }
end
package.preload["resty.ipmatcher"] = function() return {} end
-- resty.sha256 / resty.string: a 64-bit FNV-1a stands in for sha256 (no
-- OpenResty here). Only the key identity matters to this test.
package.preload["resty.sha256"] = function()
    return { new = function()
        local parts = {}
        return {
            update = function(_, s) parts[#parts + 1] = s end,
            final = function()
                local h = -3750763034362895579
                local s = table.concat(parts)
                for i = 1, #s do h = (h ~ s:byte(i)) * 1099511628211 end
                return h
            end,
        }
    end }
end
package.preload["resty.string"] = function()
    return { to_hex = function(h) return string.format("%016x", h) end }
end

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
    request = { get_method = function() return "GET" end, get_path = function() return "/" end },
    ctx = { plugin = {}, shared = {} },
}

local handler = dofile("./kong/plugins/karna/handler.lua")
local I = handler._internals
assert(I and I.conf_cache_key and I.get_plugin_dynamic_rules
       and I.get_local_request_rules and I.get_overrides_cached
       and I.get_redact_spec_cached,
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
print("\n- conf_cache_key: identity is plugin id + configuration hash, never the address")
-- ---------------------------------------------------------------------------
local c1 = conf("plugin-1", 7)
local k1 = I.conf_cache_key("p", c1)
ok(k1 and k1:match("^p:plugin%-1:%x+$") ~= nil, "format is <prefix>:<__plugin_id>:<hash> (" .. tostring(k1) .. ")")
ok(I.conf_cache_key("p", conf("plugin-1", 8)) == k1,
   "same plugin, same content, new __seq__ → same key")
ok(I.conf_cache_key("p", c1) ~= I.conf_cache_key("q", c1), "prefix is part of the key")
ok(not I.conf_cache_key("p", c1):find(tostring(c1), 1, true), "the table address is not in the key")
ok(I.conf_cache_key("p", conf("plugin-2", 7)) ~= k1, "different plugin, same content → different key")
ok(I.conf_cache_key("p", conf("plugin-1", 9, { engine_blocking_mode = true })) ~= k1,
   "same plugin, different content → different key")
ok(I.conf_cache_key("p", conf("plugin-1", nil)) == nil, "__seq__ missing → nil (no safe identity)")
ok(I.conf_cache_key("p", conf("plugin-1", 0)) == nil, "__seq__ == 0 (Kong incr-failed sentinel) → nil")
local knil = I.conf_cache_key("p", conf(nil, 7))
ok(knil and knil:match("^p:nil:%x+$") ~= nil, "__plugin_id missing but __seq__ present → still a key")

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
local all_shaped = true
for _, k in ipairs(CACHE.writes()) do
    if not k:match("^[%l_]+:plugin%-[ab]:%x+$") then all_shaped = false end
end
ok(all_shaped, "every key is <prefix>:<__plugin_id>:<hash>, no __seq__ in it")
ok(not keys_contain("table:"), "no key carries a table address")

local compiles_before = #COMPILES
ok(rawequal(I.get_local_request_rules(A), la) and rawequal(I.get_plugin_dynamic_rules(A), da)
   and rawequal(I.get_overrides_cached(A), oa), "second call on the same conf is a cache hit")
ok(#COMPILES == compiles_before, "cache hit → no recompile")
ok(rawequal(I.get_local_request_rules(B), lb), "B's hit is B's entry")

-- ---------------------------------------------------------------------------
print("\n- reconfiguration: same plugin id, higher __seq__, new rules")
-- ---------------------------------------------------------------------------
local A_HASH = I.conf_cache_key("x", A):match("^x:plugin%-a:(%x+)$")
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

-- One generation per instance: the new __seq__ replaced the old entries, and
-- a request still holding the previous table (in flight across the rebuild)
-- gets its own rules built fresh, without writing them back.
ok(not CACHE:has("local_request_rules:plugin-a:" .. A_HASH)
   and not CACHE:has("plugin_dyn_rules:plugin-a:" .. A_HASH)
   and not CACHE:has("overrides:plugin-a:" .. A_HASH), "the previous generation's entries are gone")
ok(I.conf_cache_key("local_request_rules", A) == nil,
   "the previous table's generation is dead: it has no key any more")
ok(CACHE:has(I.conf_cache_key("local_request_rules", B)), "another instance's entries are untouched")
local w_old = writes()
local la_old = I.get_local_request_rules(A)
ok(not rawequal(la_old, la) and #la_old.all == 1 and la_old.all[1].id == "svc_a_block",
   "the previous conf table still evaluates its own rules")
ok(writes() == w_old, "…built fresh and not cached, so it cannot evict the live generation")
ok(rawequal(I.get_local_request_rules(A2), la2), "the live generation is still a cache hit")

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
print("\n- get_redact_spec_cached: compiled once, and 'nothing to mask' is cached too")
-- ---------------------------------------------------------------------------
-- The audit-log redaction spec is compiled from the config and reused for every
-- logged request, so it caches like the rule packs above. The wrinkle: an LRU
-- cannot hold nil, and `compile` returns nil when nothing would ever be masked
-- — without the `false` sentinel a deployment with redaction off would
-- recompile on every single record.
local REDACT_HEADERS = { "authorization", "cookie" }

local rc1 = conf("plugin-r", 40, { auditlog_redact_enabled = true,
                                   auditlog_redact_headers = REDACT_HEADERS })
local before_r = writes()
local spec1 = I.get_redact_spec_cached(rc1)
ok(type(spec1) == "table" and spec1.names["authorization"] == "auth",
   "a spec is compiled from the config")
ok(writes() == before_r + 1, "the compile is cached (one write)")
ok(keys_contain("redact:plugin-r:"), "keyed by prefix + plugin id + hash")

local spec2 = I.get_redact_spec_cached(rc1)
ok(spec2 == spec1, "the second call returns the cached table, it does not recompile")
ok(writes() == before_r + 1, "…and writes nothing more")

-- a configuration edit lands on a new key, so the old spec is never reused
local rc2 = conf("plugin-r", 41, { auditlog_redact_enabled = true,
                                   auditlog_redact_headers = { "x-api-key" } })
local spec3 = I.get_redact_spec_cached(rc2)
ok(spec3 ~= spec1 and spec3.names["x-api-key"] == "full" and spec3.names["authorization"] == nil,
   "a new __seq__ recompiles instead of serving the previous configuration")

-- redaction off: nil spec, cached as `false`, never recompiled
local rc_off = conf("plugin-r", 42, { auditlog_redact_enabled = false })
local before_off = writes()
ok(I.get_redact_spec_cached(rc_off) == nil, "disabled → nil spec (the log phase skips the path)")
ok(writes() == before_off + 1, "the 'nothing to mask' answer is cached")
ok(I.get_redact_spec_cached(rc_off) == nil, "…and stays nil")
ok(writes() == before_off + 1, "…without a second write — no recompile per logged request")

-- no cache identity available: build fresh, never guess a key
local rc_noseq = { __plugin_id = "plugin-r", auditlog_redact_enabled = true,
                   auditlog_redact_headers = REDACT_HEADERS }
local before_ns = writes()
ok(type(I.get_redact_spec_cached(rc_noseq)) == "table", "no __seq__ → still a usable spec")
ok(writes() == before_ns, "…and nothing is cached under a guessed key")

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

-- ---------------------------------------------------------------------------
print("\n- one generation per instance: entries do not grow with reconfigurations")
-- ---------------------------------------------------------------------------
-- K instances, R rounds in which EVERY instance's content changes (a new
-- `revision` value), all five per-config caches populated each round: the
-- cache must hold K x 5 entries after the first round and after the last,
-- whatever R is. (When only __seq__ changes nothing is rebuilt at all, see
-- the next section.)
local RULE_G = fixture(
    '{"id":"gen_block","phase":"access","action":{"fixed_response":{"status_code":403}}}',
    { id = "gen_block", phase = "access", action = { fixed_response = { status_code = 403 } } })
local SEC_G = 'SecRule ARGS "@rx g" "id:100009,phase:2,deny"'
local function full_conf(pid, seq, rev)
    return conf(pid, seq, {
        revision = rev or 0,
        rules_request = { RULE_G }, custom_secrules = { SEC_G },
        rule_action_overrides = { OVR_A },
        limit_arg_num_overrides = { { path_rx = "^/upload", methods = { "POST" }, limit = 500 } },
        auditlog_redact_enabled = true, auditlog_redact_headers = REDACT_HEADERS,
    })
end
local function touch_all(c)
    I.get_local_request_rules(c); I.get_plugin_dynamic_rules(c); I.get_overrides_cached(c)
    I.resolve_arg_limit_override(c); I.get_redact_spec_cached(c)
end

CACHE:flush_all()
local K, R, PREFIXES = 40, 30, 5
local seq = 1000
local after_first, max_seen = nil, 0
for round = 1, R do
    for k = 1, K do
        seq = seq + 1
        touch_all(full_conf("gen-" .. k, seq, round))
    end
    if round == 1 then after_first = CACHE:count() end
    if CACHE:count() > max_seen then max_seen = CACHE:count() end
end
ok(after_first == K * PREFIXES, "after the first round: K x prefixes entries (" .. tostring(after_first) .. ")")
ok(CACHE:count() == K * PREFIXES, "after " .. R .. " rounds: still K x prefixes (" .. CACHE:count() .. ")")
ok(max_seen == K * PREFIXES, "never above K x prefixes in between")

-- A rebuild of one instance does not cost the others their compiled sets.
local live = {}
for k = 1, K do live[k] = full_conf("gen-" .. k, seq - K + k, R) end
local before_c = #COMPILES
for k = 1, K do touch_all(live[k]) end
ok(#COMPILES == before_c, "every live generation is a hit, no recompile")
seq = seq + 1
local g1_new = full_conf("gen-1", seq, R + 1)
touch_all(g1_new)
ok(#COMPILES == before_c + 2, "the reconfigured instance recompiles once (rules_request + dynamic)")
for k = 2, K do touch_all(live[k]) end
ok(#COMPILES == before_c + 2, "the other instances keep their compiled sets")
ok(CACHE:count() == K * PREFIXES, "still K x prefixes entries")

-- In-flight requests on the old table interleaved with the new one: the old
-- table recompiles each time (it is never cached), the new one stays a hit,
-- and the two never displace each other.
before_c = #COMPILES
for _ = 1, 5 do touch_all(live[1]); touch_all(g1_new) end
ok(#COMPILES == before_c + 10, "old table: fresh build per call (5 x 2), new table: no compile")
ok(CACHE:has(I.conf_cache_key("local_request_rules", g1_new)), "the new generation is still cached")
ok(CACHE:count() == K * PREFIXES, "and the entry count did not move")

-- ---------------------------------------------------------------------------
print("\n- only __seq__ changed: nothing is rebuilt")
-- ---------------------------------------------------------------------------
-- After a write to ANY plugin, Kong hands every Karna instance a new config
-- table with a new __seq__ and, almost always, the same content. The compiled
-- sets must then be reused as they are: no compile, no cache write.
local function rebuilt(c, new_seq)
    local copy = deep_copy(c)
    copy.__seq__ = new_seq
    return copy
end
local same0 = full_conf("same-1", seq + 1, 7)
seq = seq + 1
touch_all(same0)
local s_lrr, s_dyn, s_ovr = I.get_local_request_rules(same0), I.get_plugin_dynamic_rules(same0),
                            I.get_overrides_cached(same0)
local s_red = I.get_redact_spec_cached(same0)
local c0, w0 = #COMPILES, writes()
for _ = 1, 5 do
    seq = seq + 1
    local again = rebuilt(same0, seq)
    touch_all(again)
    ok(rawequal(I.get_local_request_rules(again), s_lrr) and rawequal(I.get_plugin_dynamic_rules(again), s_dyn)
       and rawequal(I.get_overrides_cached(again), s_ovr) and rawequal(I.get_redact_spec_cached(again), s_red),
       "__seq__ " .. seq .. ": every getter returns the compiled set already built")
end
ok(#COMPILES == c0, "no compile across five rebuilds")
ok(writes() == w0, "no cache write across five rebuilds")
ok(rawequal(I.get_local_request_rules(same0), s_lrr), "the first table keeps hitting too")

-- the key does not depend on the order keys were inserted into the table
local reversed = {}
do
    local ks = {}
    for k in pairs(same0) do ks[#ks + 1] = tostring(k) end
    table.sort(ks, function(a, b) return a > b end)
    for _, k in ipairs(ks) do reversed[k] = deep_copy(same0[k]) end
    seq = seq + 1
    reversed.__seq__ = seq
end
ok(I.conf_cache_key("overrides", reversed) == I.conf_cache_key("overrides", same0),
   "same content inserted in another order → same key")
-- array order is content: rules run in order
local swapped = rebuilt(same0, seq + 1)
seq = seq + 1
swapped.auditlog_redact_headers = { REDACT_HEADERS[2], REDACT_HEADERS[1] }
ok(I.conf_cache_key("redact", swapped) ~= I.conf_cache_key("redact", reversed),
   "same elements in another array order → different key")

-- a value the encoding cannot pin (a function) can only cost a recompile
local fn1, fn2 = function() end, function() end
local f1 = conf("fn-1", seq + 1, { odd = fn1 })
local f2 = conf("fn-1", seq + 2, { odd = fn1 })
local f3 = conf("fn-1", seq + 3, { odd = fn2 })
seq = seq + 3
local kf1 = I.conf_cache_key("overrides", f1)
ok(I.conf_cache_key("overrides", f2) == kf1, "same function value → same key")
ok(I.conf_cache_key("overrides", f3) ~= kf1, "a different function value → a different key, never a shared one")

-- ---------------------------------------------------------------------------
print("\n- a table replaced while in use never writes its generation back")
-- ---------------------------------------------------------------------------
-- A request that started before the change still holds the old table, and
-- its log phase builds the redaction spec after the new table has taken over.
local old_t = full_conf("inflight-1", seq + 1, 1)
seq = seq + 1
touch_all(old_t)
local new_t = full_conf("inflight-1", seq + 1, 2)
seq = seq + 1
touch_all(new_t)
local cnt, w1 = CACHE:count(), writes()
local spec_old = I.get_redact_spec_cached(old_t)
ok(type(spec_old) == "table", "the old table still gets a usable redaction spec")
I.get_local_request_rules(old_t); I.get_overrides_cached(old_t); I.get_plugin_dynamic_rules(old_t)
ok(writes() == w1 and CACHE:count() == cnt, "…built fresh, nothing written back under the dead generation")

-- ---------------------------------------------------------------------------
print("\n- every schema field is part of the identity")
-- ---------------------------------------------------------------------------
-- The hash covers the whole configuration, so changing ANY field of the Karna
-- schema must give a new key and a fresh compile. Walks the real schema.lua,
-- nested records included, so a field added tomorrow is covered the day it
-- lands.
package.preload["kong.db.schema.typedefs"] = function()
    return { no_consumer = { type = "foreign" }, protocols_http = { type = "set" } }
end
local schema = assert(loadfile("./kong/plugins/karna/schema.lua"))("kong.plugins.karna.schema")
local config_fields
for _, f in ipairs(schema.fields) do
    if f.config then config_fields = f.config.fields end
end
assert(config_fields, "schema: no config record")

local function defaults_of(fields)
    local out = {}
    for _, f in ipairs(fields) do
        local name, def = next(f)
        if def.type == "record" then
            out[name] = defaults_of(def.fields)
        elseif def.default ~= nil then
            out[name] = deep_copy(def.default)
        end
    end
    return out
end
local function mutated(def, cur)
    local t = def.type
    if t == "boolean" then return not cur end
    if t == "number" or t == "integer" then return (cur or 0) + 1 end
    if t == "string" then return (cur or "") .. "x" end
    if t == "array" or t == "set" then
        local v = deep_copy(cur or {})
        local et = def.elements and def.elements.type
        v[#v + 1] = (et == "number" or et == "integer") and 1 or (et == "record") and {} or "x"
        return v
    end
    if t == "map" then
        local v = deep_copy(cur or {})
        v["x"] = "x"
        return v
    end
    error("schema field of an unhandled type: " .. tostring(t))
end

local BASE = defaults_of(config_fields)
BASE.__plugin_id = "schema-1"
BASE.route_id, BASE.service_id, BASE.plugin_instance_name = nil, "svc-1", nil
local cases = {}
for _, f in ipairs(config_fields) do
    local name, def = next(f)
    if def.type == "record" then
        for _, sf in ipairs(def.fields) do
            local sname, sdef = next(sf)
            cases[#cases + 1] = { label = name .. "." .. sname, apply = function(c)
                c[name][sname] = mutated(sdef, c[name][sname]) end }
        end
    else
        cases[#cases + 1] = { label = name, apply = function(c) c[name] = mutated(def, c[name]) end }
    end
end
ok(#cases > 50, "the schema walk found " .. #cases .. " fields")

local missed = {}
for _, case in ipairs(cases) do
    -- the base content is the live generation...
    seq = seq + 1
    local b = deep_copy(BASE); b.__seq__ = seq
    local keys_b = {}
    for _, pfx in ipairs({ "plugin_dyn_rules", "local_request_rules", "overrides", "arg_limits", "redact" }) do
        keys_b[pfx] = I.conf_cache_key(pfx, b)
    end
    local ovr_b = I.get_overrides_cached(b)
    -- ...then the same content with one field changed arrives
    seq = seq + 1
    local m = deep_copy(BASE); m.__seq__ = seq
    case.apply(m)
    local differs = true
    for pfx, kb in pairs(keys_b) do
        if I.conf_cache_key(pfx, m) == kb then differs = false end
    end
    if not differs or rawequal(I.get_overrides_cached(m), ovr_b) then
        missed[#missed + 1] = case.label
    end
end
ok(#missed == 0, "changing any one field gives a new key on every prefix and a fresh compile"
   .. (#missed > 0 and (" — missed: " .. table.concat(missed, ", ")) or ""))

-- The Kong stamps that name the instance are in the hash too; only __seq__
-- is left out.
seq = seq + 1
local st1 = deep_copy(BASE); st1.__seq__ = seq
local kst = I.conf_cache_key("overrides", st1)
seq = seq + 1
local st2 = deep_copy(BASE); st2.__seq__ = seq; st2.route_id = "route-2"
ok(I.conf_cache_key("overrides", st2) ~= kst, "a Kong stamp (route_id) change → new key")

-- ---------------------------------------------------------------------------
print("\n- CRS exclusion plugin files on disk are part of the identity")
-- ---------------------------------------------------------------------------
-- plugin_dyn_rules parses the enabled plugins' .conf files from disk. A
-- rebuild has always picked up an edit there, and still does.
local WP_DIR = "/opt/coreruleset-plugins/wp-excl/plugins/"
DISK[WP_DIR] = { ["wp.conf"] = 'SecRule ARGS "@rx w" "id:100020,phase:2,deny"' }
local wp1 = conf("disk-1", seq + 1, { crs_plugins_enabled = { "wp-excl" } })
seq = seq + 1
local d_wp1 = I.get_plugin_dynamic_rules(wp1)
ok(d_wp1.detection.access[1].id == "100020", "the plugin file's rule is loaded")
local wp2 = rebuilt(wp1, seq + 1); seq = seq + 1
ok(rawequal(I.get_plugin_dynamic_rules(wp2), d_wp1), "same files, new __seq__ → reused")
DISK[WP_DIR] = { ["wp.conf"] = 'SecRule ARGS "@rx w2" "id:100021,phase:2,deny"' }
local wp3 = rebuilt(wp1, seq + 1); seq = seq + 1
local d_wp3 = I.get_plugin_dynamic_rules(wp3)
ok(not rawequal(d_wp3, d_wp1) and d_wp3.detection.access[1].id == "100021",
   "a file edited on disk, new __seq__ → reparsed")
DISK[WP_DIR] = nil

-- ---------------------------------------------------------------------------
print("\n- the CRS pack lives outside the per-config LRU")
-- ---------------------------------------------------------------------------
-- The CRS pack is loaded once in init_worker and never reloaded. If it shared
-- the LRU with the per-instance entries, pressure on the LRU could evict it and
-- the access phase would skip CRS evaluation without a word.
local CRS_RULES = { { id = "crs-1", phase = "access" }, { id = "crs-2", phase = "access" } }
local CRS_RCONTROL = { { id = "crs-ctl-1", phase = "access" } }
package.loaded["kong.plugins.karna.ka_engine"].load_rules = function()
    return CRS_RULES, CRS_RCONTROL, { ["data.txt"] = { "x" } }
end
package.loaded["kong.plugins.karna.ka_global_rules"].init = function() end
package.loaded["kong.plugins.karna.ka_tls"].init = function() end
package.loaded["kong.plugins.karna.ka_re2_gate"].build = function() return nil end
local w_init = writes()
handler:init_worker()
local r1, rc1c, df1 = I.crs_pack()
ok(rawequal(r1, CRS_RULES) and rawequal(rc1c, CRS_RCONTROL) and df1["data.txt"] ~= nil,
   "init_worker loads the CRS pack")
ok(writes() == w_init and CACHE:count() == 0, "init_worker writes nothing to the per-config LRU")

-- saturate the LRU three times over with per-instance entries
local cap = CACHE.size
for i = 1, cap * 3 do
    seq = seq + 1
    I.get_overrides_cached(conf("sat-" .. i, seq, { rule_action_overrides = { OVR_A } }))
end
ok(CACHE:count() == cap, "the LRU is full (" .. CACHE:count() .. " / " .. cap .. ")")
local r2, rc2, df2 = I.crs_pack()
ok(rawequal(r2, CRS_RULES) and rawequal(rc2, CRS_RCONTROL) and rawequal(df2, df1),
   "the CRS pack is still there after saturating the LRU")
ok(cap == 2000 * PREFIXES, "capacity is sized as instances x prefixes")

print(string.format("\n%d test(s) failed", fails))
os.exit(fails == 0 and 0 or 1)
