-- external_log_entries.lua
-- Unit tests for ka_utils.build_external_matches — the normaliser that
-- turns kong.ctx.shared.karna.log_entries[] (written by sibling Kong
-- plugins) into the audit log v2 external_matches[] array.
--
-- The function is replicated inline here to keep the test free of
-- ngx/kong globals. Keep this copy in sync with the source of truth at
-- kong/plugins/karna/modules/ka_utils.lua → _M.build_external_matches.

local lu = require("luaunit")
local cjson = require("cjson")

local function build_external_matches(raw_entries)
    if type(raw_entries) ~= "table" or #raw_entries == 0 then
        return cjson.empty_array
    end
    local out = {}
    for _, e in ipairs(raw_entries) do
        if type(e) == "table"
            and type(e.source) == "string"
            and type(e.rule_id) == "string"
            and type(e.message) == "string" then
            local entry = {
                source  = string.sub(e.source, 1, 100),
                rule_id = string.sub(e.rule_id, 1, 100),
                message = string.sub(e.message, 1, 1000),
            }
            if type(e.tags) == "table" then
                entry.tags = e.tags
            end
            if type(e.metadata) == "table" then
                entry.metadata = e.metadata
            end
            out[#out + 1] = entry
        end
    end
    if #out == 0 then
        return cjson.empty_array
    end
    return out
end

TestExternalLogEntries = {}

function TestExternalLogEntries:test_nil_input_returns_empty_array()
    lu.assertEquals(build_external_matches(nil), cjson.empty_array)
end

function TestExternalLogEntries:test_empty_table_returns_empty_array()
    lu.assertEquals(build_external_matches({}), cjson.empty_array)
end

function TestExternalLogEntries:test_non_table_input_returns_empty_array()
    lu.assertEquals(build_external_matches("string"), cjson.empty_array)
    lu.assertEquals(build_external_matches(42), cjson.empty_array)
    lu.assertEquals(build_external_matches(true), cjson.empty_array)
end

function TestExternalLogEntries:test_valid_minimal_entry()
    local r = build_external_matches({{
        source  = "my-plugin",
        rule_id = "RL-001",
        message = "Something happened"
    }})
    lu.assertEquals(#r, 1)
    lu.assertEquals(r[1].source,  "my-plugin")
    lu.assertEquals(r[1].rule_id, "RL-001")
    lu.assertEquals(r[1].message, "Something happened")
    lu.assertNil(r[1].tags)
    lu.assertNil(r[1].metadata)
end

function TestExternalLogEntries:test_entry_with_tags_and_metadata()
    local r = build_external_matches({{
        source   = "my-plugin",
        rule_id  = "RL-001",
        message  = "Done",
        tags     = {"a", "b"},
        metadata = { key = "value", count = 7 }
    }})
    lu.assertEquals(#r, 1)
    lu.assertEquals(r[1].tags, {"a", "b"})
    lu.assertEquals(r[1].metadata, { key = "value", count = 7 })
end

function TestExternalLogEntries:test_malformed_entries_silently_dropped()
    local r = build_external_matches({
        { source = "valid-a",            rule_id = "1", message = "ok"  },
        { source = "missing-message",    rule_id = "2"                  },  -- drop
        "not-a-table",                                                       -- drop
        { source = 42, rule_id = "3", message = "non-string source"     },  -- drop
        { source = "valid-b",            rule_id = "4", message = "ok2" },
    })
    lu.assertEquals(#r, 2)
    lu.assertEquals(r[1].source, "valid-a")
    lu.assertEquals(r[2].source, "valid-b")
end

function TestExternalLogEntries:test_oversize_strings_are_clipped()
    local r = build_external_matches({{
        source  = string.rep("a",  200),
        rule_id = string.rep("b",  200),
        message = string.rep("c", 2000),
    }})
    lu.assertEquals(#r[1].source,  100)
    lu.assertEquals(#r[1].rule_id, 100)
    lu.assertEquals(#r[1].message, 1000)
end

function TestExternalLogEntries:test_all_dropped_returns_empty_array()
    lu.assertEquals(build_external_matches({ "not-a-table", 42 }), cjson.empty_array)
end

function TestExternalLogEntries:test_tags_not_a_table_is_dropped()
    local r = build_external_matches({{
        source  = "p", rule_id = "1", message = "m",
        tags    = "not-an-array",
    }})
    lu.assertEquals(#r, 1)
    lu.assertNil(r[1].tags)
end

function TestExternalLogEntries:test_metadata_not_a_table_is_dropped()
    local r = build_external_matches({{
        source   = "p", rule_id = "1", message = "m",
        metadata = "not-an-object",
    }})
    lu.assertEquals(#r, 1)
    lu.assertNil(r[1].metadata)
end

os.exit(lu.LuaUnit.run())
