-- ka-unittest/external_log_entries_v1.lua
--
-- Guards the audit log v1 side of the sibling-plugin logging contract:
-- entries queued on kong.ctx.shared.karna.log_entries must surface as
-- transaction.messages[] elements, using the exact message shape Karna
-- already emits for a rule match.
--
-- Why it matters: a sibling plugin that terminates the response itself (an
-- html-to-markdown transformer calling kong.response.exit() in the response
-- phase, say) has no other way into the audit trail. Before this, a v1
-- deployment simply lost the event — v2 published it under external_matches[]
-- and v1 published nothing.
--
-- Load-bearing properties pinned here:
--   1. a v1 document with no external entries is unchanged, field for field
--      (the whole point of a legacy format is that it does not move);
--   2. the validation is the SAME one v2 uses (build_external_matches), so
--      the two surfaces cannot drift on what a valid entry is;
--   3. no new keys anywhere in the document — an existing Vector /
--      Elasticsearch mapping keeps working untouched;
--   4. metadata is NOT flattened into the v1 free-text field;
--   5. the shared cjson.empty_array sentinel is never mutated.
--
-- Unlike the older external_log_entries.lua (which replicates the SUT
-- inline), this test loads the REAL ka_utils.lua behind ngx/kong stubs, so
-- it cannot drift from the source at all.
--
-- Run from repo root:
--   lua    ka-unittest/external_log_entries_v1.lua
--   luajit ka-unittest/external_log_entries_v1.lua

local fails = 0
local function ok(cond, name)
    if cond then print("  ok  - " .. name)
    else print("  FAIL- " .. name); fails = fails + 1 end
end

-- ---------------------------------------------------------------------------
-- stubs: cjson (only empty_array is used on these paths) + the version module
-- ---------------------------------------------------------------------------
-- `empty_array` is deliberately NOT a table. In the real lua-cjson that ships
-- with OpenResty it is a LIGHTUSERDATA sentinel, so any code that treats it as
-- an empty table (ipairs, #, indexing) throws — and a throw inside log_by_lua
-- drops the whole audit record with nothing but an error-log line to show for
-- it. That is exactly the bug this stub reproduces: with a table here the test
-- passes while production loses every record that has external entries and no
-- rule match. A coroutine is the closest non-table stand-in pure Lua can make:
-- type() is not "table" and indexing it raises, same as the sentinel.
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
    -- .5 exactly: the v2 timestamp does string.format("%03d", frac * 1000),
    -- and Lua 5.4 rejects a float with no exact integer representation.
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
        get_headers = function() return { ["content-type"] = "text/markdown" } end,
    },
    service = {
        response = {
            get_status  = function() return 200 end,
            get_headers = function() return { ["content-type"] = "text/markdown" } end,
        },
    },
}

local utils = dofile("./kong/plugins/karna/modules/ka_utils.lua")

-- ---------------------------------------------------------------------------
-- fixtures
-- ---------------------------------------------------------------------------
local PLUGIN_CONF = { engine_blocking_mode = true, paranoia_level = 1 }

local function set_entries(entries)
    kong.ctx.shared = {}
    if entries ~= nil then
        kong.ctx.shared.karna = { log_entries = entries }
    end
end

local function markdown_entry()
    return {
        source   = "markdown-for-agent",
        rule_id  = "html2markdown",
        message  = "HTML response transformed to Markdown",
        tags     = { "response-transform" },
        metadata = { transform = "html2markdown", bytes = 4096 },
    }
end

-- a Karna rule match, in the shape handler.lua hands to get_auditlog
local RULE = { id = "942100", message = "SQL Injection Attack Detected", tags = { "attack-sqli" } }
local PARTS = { { matched_on = "request.arg.value:q", matched_value = "1 OR 1=1" } }

local function keyset(t)
    local ks = {}
    for k in pairs(t) do ks[#ks + 1] = tostring(k) end
    table.sort(ks)
    return table.concat(ks, ",")
end

-- ============================================================
print("- no external entries: the v1 document does not move")
-- ============================================================
set_entries(nil)
local baseline_nomatch = utils:get_auditlog(nil, nil)
local baseline_match   = utils:get_auditlog(RULE, PARTS)

ok(baseline_nomatch.transaction.messages == CJSON.empty_array,
   "no kong.ctx.shared.karna at all → messages stays the empty_array sentinel")

set_entries(nil)
kong.ctx.shared.karna = {}                                  -- present, no log_entries
local doc = utils:get_auditlog(nil, nil)
ok(doc.transaction.messages == CJSON.empty_array, "karna table without log_entries → unchanged")

set_entries({})                                             -- present but empty
doc = utils:get_auditlog(nil, nil)
ok(doc.transaction.messages == CJSON.empty_array, "empty log_entries → unchanged")

set_entries("not-a-table")
doc = utils:get_auditlog(nil, nil)
ok(doc.transaction.messages == CJSON.empty_array, "log_entries of the wrong type → unchanged")

set_entries(nil)
doc = utils:get_auditlog(RULE, PARTS)
ok(#doc.transaction.messages == 1 and doc.transaction.messages[1].details.ruleId == "942100",
   "rule match with no external entries → the single Karna message, as before")
ok(keyset(doc) == keyset(baseline_match) and keyset(doc.transaction) == keyset(baseline_match.transaction),
   "same top-level and transaction-level keys as before the feature")

-- ============================================================
print("")
print("- one valid entry becomes one transaction.messages[] element")
-- ============================================================
set_entries({ markdown_entry() })
doc = utils:get_auditlog(nil, nil)
ok(#doc.transaction.messages == 1, "one message emitted")
local m = doc.transaction.messages[1]
ok(m.message == "HTML response transformed to Markdown", "message carries the entry message")
ok(m.details.ruleId == "html2markdown", "rule_id → details.ruleId")
ok(m.details.data == "Source: markdown-for-agent", "source → details.data")
ok(m.details.tags[1] == "response-transform", "tags → details.tags")
ok(keyset(m) == "details,message", "message object has only message + details")
ok(keyset(m.details) == "data,ruleId,tags", "details has only the three v1 keys")

-- ============================================================
print("")
print("- no new top-level fields, and metadata is not leaked into v1")
-- ============================================================
ok(keyset(doc) == keyset(baseline_nomatch), "top-level keys identical to a document without entries")
ok(keyset(doc.transaction) == keyset(baseline_nomatch.transaction), "transaction keys identical")
ok(doc.external_matches == nil and doc.transaction.external_matches == nil,
   "external_matches is not smuggled into v1")
ok(m.details.metadata == nil and m.metadata == nil, "metadata is dropped, not copied")
ok(not string.find(m.details.data, "html2markdown", 1, true),
   "metadata is not flattened into the free-text data field")

-- ============================================================
print("")
print("- tags: passed through, empty array when absent")
-- ============================================================
set_entries({ { source = "p", rule_id = "r", message = "m" } })
doc = utils:get_auditlog(nil, nil)
ok(doc.transaction.messages[1].details.tags == CJSON.empty_array, "absent tags → empty array, key still present")

-- ============================================================
print("")
print("- several entries in one request, in order")
-- ============================================================
set_entries({
    { source = "plugin-a", rule_id = "a1", message = "first"  },
    { source = "plugin-b", rule_id = "b1", message = "second" },
    { source = "plugin-c", rule_id = "c1", message = "third"  },
})
doc = utils:get_auditlog(nil, nil)
ok(#doc.transaction.messages == 3, "all three kept")
ok(doc.transaction.messages[1].message == "first"
   and doc.transaction.messages[2].message == "second"
   and doc.transaction.messages[3].message == "third", "queue order preserved")

-- ============================================================
print("")
print("- malformed entries are dropped, the rest still logs")
-- ============================================================
set_entries({
    { source = "valid-a", rule_id = "1", message = "ok" },
    { source = "missing-message", rule_id = "2" },              -- drop
    "not-a-table",                                              -- drop
    { source = 42, rule_id = "3", message = "non-string" },     -- drop
    { source = "valid-b", rule_id = "4", message = "ok2", tags = "not-an-array" },
})
doc = utils:get_auditlog(nil, nil)
ok(#doc.transaction.messages == 2, "only the two valid entries survive")
ok(doc.transaction.messages[1].details.ruleId == "1"
   and doc.transaction.messages[2].details.ruleId == "4", "the surviving pair is the right one")
ok(doc.transaction.messages[2].details.tags == CJSON.empty_array, "a non-array tags is ignored, not fatal")

set_entries({ "not-a-table", 42, { source = "p" } })
doc = utils:get_auditlog(nil, nil)
ok(doc.transaction.messages == CJSON.empty_array, "every entry invalid → document unchanged")

-- ============================================================
print("")
print("- oversize strings clipped exactly like v2")
-- ============================================================
set_entries({ {
    source  = string.rep("a", 200),
    rule_id = string.rep("b", 200),
    message = string.rep("c", 2000),
} })
doc = utils:get_auditlog(nil, nil)
m = doc.transaction.messages[1]
ok(#m.message == 1000, "message clipped at 1000")
ok(#m.details.ruleId == 100, "ruleId clipped at 100")
ok(#m.details.data == #"Source: " + 100, "source clipped at 100")

-- ============================================================
print("")
print("- a Karna rule match and external entries coexist")
-- ============================================================
set_entries({ markdown_entry(), { source = "plugin-b", rule_id = "b1", message = "second" } })
doc = utils:get_auditlog(RULE, PARTS)
ok(#doc.transaction.messages == 3, "rule message + two external messages")
ok(doc.transaction.messages[1].details.ruleId == "942100", "the rule match comes first, unmodified")
ok(doc.transaction.messages[1].details.data == "Matched on: request.arg.value:q - Matched value: 1 OR 1=1",
   "the rule message keeps its own matched-parts data")
ok(doc.transaction.messages[2].details.ruleId == "html2markdown"
   and doc.transaction.messages[3].details.ruleId == "b1", "external messages follow")

-- ============================================================
print("")
print("- the shared empty_array sentinel is never written through")
-- ============================================================
-- Two properties in one: the sentinel is still the exact object it was (no
-- document turned it into a real table), and appending external messages to a
-- document whose `messages` IS the sentinel does not try to read it as a
-- table. The stub throws on indexing, so a regression here fails loudly
-- instead of quietly costing the record in production.
ok(type(CJSON.empty_array) ~= "table", "the sentinel is still not a table")
set_entries({ markdown_entry() })
local built, err = pcall(function() return utils:get_auditlog(nil, nil) end)
ok(built, "appending onto a sentinel `messages` never indexes it: " .. tostring(err))

-- ============================================================
print("")
print("- auditlog_only_on_match: one external event is enough")
-- ============================================================
-- SUT — copy of the gate in handler.lua:log (the only piece of this feature
-- that lives outside ka_utils). KEEP IN SYNC.
local function writes_log(only_on_match, loggable_matches, shared)
    local has_external_entries = false
    if shared.karna
       and type(shared.karna.log_entries) == "table"
       and #shared.karna.log_entries > 0 then
        has_external_entries = true
    end
    if only_on_match and #loggable_matches == 0 and not has_external_entries then
        return false
    end
    return true
end

ok(writes_log(true, {}, { karna = { log_entries = { markdown_entry() } } }),
   "only_on_match + no rule match + one external entry → the log is written")
ok(not writes_log(true, {}, {}), "only_on_match + nothing at all → still no log")
ok(writes_log(true, { "a-match" }, {}), "only_on_match + a rule match → log, as before")
ok(writes_log(false, {}, {}), "only_on_match off → log on every request, as before")

set_entries({ markdown_entry() })
doc = utils:get_auditlog(nil, nil)
ok(#doc.transaction.messages == 1 and doc.transaction.messages[1].details.ruleId == "html2markdown",
   "and that document does carry the event (no rule match anywhere in it)")

-- ============================================================
print("")
print("- v2 is untouched")
-- ============================================================
set_entries({ markdown_entry() })
local v2 = utils:get_auditlog_v2({}, PLUGIN_CONF)
ok(v2.version == "2.0", "still a v2 document")
ok(#v2.external_matches == 1, "the entry is still published under external_matches")
local em = v2.external_matches[1]
ok(em.source == "markdown-for-agent" and em.rule_id == "html2markdown"
   and em.message == "HTML response transformed to Markdown", "same fields as before")
ok(em.tags[1] == "response-transform", "tags passed through")
ok(em.metadata and em.metadata.transform == "html2markdown",
   "metadata still passed through in v2 — only v1 drops it")
ok(keyset(em) == "message,metadata,rule_id,source,tags", "no extra keys in the v2 entry")
ok(v2.transaction == nil and v2.messages == nil, "v2 gained nothing from the v1 mapping")

set_entries(nil)
v2 = utils:get_auditlog_v2({}, PLUGIN_CONF)
ok(v2.external_matches == CJSON.empty_array, "no entries → external_matches is the empty array, as before")

print(string.format("\n%d test(s) failed", fails))
os.exit(fails == 0 and 0 or 1)
