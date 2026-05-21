-- set_variable_action.lua
-- Unit tests for ka_engine.apply_set_variable — the rule action helper that
-- writes a value into kong.ctx.plugin (scope "plugin") or kong.ctx.shared
-- (scope "shared"), with optional %{...} template resolution when the value
-- is a string.
--
-- The function is replicated inline here to keep the test free of
-- ngx/kong globals. Keep this copy in sync with the source of truth at
-- kong/plugins/karna/modules/ka_engine.lua → _M.apply_set_variable.

local lu = require("luaunit")
local string_find = string.find

local function apply_set_variable(self, sv, ctx_plugin, ctx_shared)
    if type(sv) ~= "table" then return false end
    if type(sv.name) ~= "string" or sv.name == "" then return false end
    if sv.value == nil then return false end

    local resolved_value = sv.value
    if type(resolved_value) == "string" and string_find(resolved_value, "%%{", 1, false) then
        resolved_value = self:replace_variable_in_string(resolved_value)
    end

    if sv.type == "plugin" then
        if type(ctx_plugin) ~= "table" then return false end
        ctx_plugin[sv.name] = resolved_value
        return true
    elseif sv.type == "shared" then
        if type(ctx_shared) ~= "table" then return false end
        ctx_shared[sv.name] = resolved_value
        return true
    end
    return false
end

-- A `self` mock that records calls and returns a sentinel.
local function make_self(resolve_to)
    local s = { _calls = {} }
    s.replace_variable_in_string = function(self, str)
        table.insert(self._calls, str)
        return resolve_to
    end
    return s
end

TestApplySetVariable = {}

function TestApplySetVariable:test_non_table_sv_returns_false()
    lu.assertFalse(apply_set_variable(make_self(""), nil, {}, {}))
    lu.assertFalse(apply_set_variable(make_self(""), "string", {}, {}))
    lu.assertFalse(apply_set_variable(make_self(""), 42, {}, {}))
end

function TestApplySetVariable:test_missing_name_returns_false()
    lu.assertFalse(apply_set_variable(make_self(""),
        { value = 1, type = "shared" }, {}, {}))
end

function TestApplySetVariable:test_empty_name_returns_false()
    lu.assertFalse(apply_set_variable(make_self(""),
        { name = "", value = 1, type = "shared" }, {}, {}))
end

function TestApplySetVariable:test_non_string_name_returns_false()
    lu.assertFalse(apply_set_variable(make_self(""),
        { name = 42, value = 1, type = "shared" }, {}, {}))
end

function TestApplySetVariable:test_nil_value_returns_false()
    lu.assertFalse(apply_set_variable(make_self(""),
        { name = "x", value = nil, type = "shared" }, {}, {}))
end

function TestApplySetVariable:test_false_value_is_accepted()
    -- `false` is a legitimate "off-switch" value for shared booleans
    local shared = {}
    lu.assertTrue(apply_set_variable(make_self(""),
        { name = "skip_x", value = false, type = "shared" }, {}, shared))
    lu.assertEquals(shared.skip_x, false)
end

function TestApplySetVariable:test_plugin_scope_writes_to_ctx_plugin()
    local plugin, shared = {}, {}
    lu.assertTrue(apply_set_variable(make_self(""),
        { name = "x", value = "hello", type = "plugin" }, plugin, shared))
    lu.assertEquals(plugin.x, "hello")
    lu.assertNil(shared.x)
end

function TestApplySetVariable:test_shared_scope_writes_to_ctx_shared()
    local plugin, shared = {}, {}
    lu.assertTrue(apply_set_variable(make_self(""),
        { name = "x", value = "hello", type = "shared" }, plugin, shared))
    lu.assertEquals(shared.x, "hello")
    lu.assertNil(plugin.x)
end

function TestApplySetVariable:test_missing_type_returns_false()
    -- Documented: callers MUST specify an explicit scope. The action is a no-op
    -- otherwise.
    local plugin, shared = {}, {}
    lu.assertFalse(apply_set_variable(make_self(""),
        { name = "x", value = "hello" }, plugin, shared))
    lu.assertNil(plugin.x); lu.assertNil(shared.x)
end

function TestApplySetVariable:test_unknown_type_returns_false()
    local plugin, shared = {}, {}
    lu.assertFalse(apply_set_variable(make_self(""),
        { name = "x", value = "hello", type = "global" }, plugin, shared))
    lu.assertNil(plugin.x); lu.assertNil(shared.x)
end

function TestApplySetVariable:test_ctx_plugin_not_a_table_returns_false()
    lu.assertFalse(apply_set_variable(make_self(""),
        { name = "x", value = 1, type = "plugin" }, nil, {}))
end

function TestApplySetVariable:test_ctx_shared_not_a_table_returns_false()
    lu.assertFalse(apply_set_variable(make_self(""),
        { name = "x", value = 1, type = "shared" }, {}, nil))
end

function TestApplySetVariable:test_numeric_value_passed_through_unchanged()
    local shared = {}
    lu.assertTrue(apply_set_variable(make_self(""),
        { name = "n", value = 42, type = "shared" }, {}, shared))
    lu.assertEquals(shared.n, 42)
end

function TestApplySetVariable:test_table_value_passed_through_unchanged()
    local tbl = { a = 1, b = 2 }
    local shared = {}
    lu.assertTrue(apply_set_variable(make_self(""),
        { name = "t", value = tbl, type = "shared" }, {}, shared))
    lu.assertEquals(shared.t, tbl)
end

function TestApplySetVariable:test_string_value_without_template_not_resolved()
    local self_mock = make_self("MUST-NOT-BE-USED")
    local shared = {}
    apply_set_variable(self_mock,
        { name = "h", value = "plain string", type = "shared" }, {}, shared)
    lu.assertEquals(shared.h, "plain string")
    lu.assertEquals(#self_mock._calls, 0)  -- resolver not invoked
end

function TestApplySetVariable:test_string_value_with_template_is_resolved()
    local self_mock = make_self("example.com")
    local shared = {}
    apply_set_variable(self_mock,
        { name = "h", value = "%{request.header.value:host}", type = "shared" }, {}, shared)
    lu.assertEquals(shared.h, "example.com")
    lu.assertEquals(#self_mock._calls, 1)
    lu.assertEquals(self_mock._calls[1], "%{request.header.value:host}")
end

os.exit(lu.LuaUnit.run())
