-- ka_compile.lua — Rule-to-closure compiler for the Karna engine.
--
-- Workstream #2 of the perf plan (`bench/notes/rule-to-closure-plan.md`).
-- Operates POST-PARSE on the internal Lua-table rule shape that every
-- rule source already produces (CRS disk files, coreruleset_fix.lua,
-- crs_plugins, custom_secrules, rules_request JSON). The compiler is
-- allowed to refuse — when it returns nil the engine falls back to the
-- table-walk in `__match_rule_conditions_impl`.
--
-- Stage 1 (this commit): every rule gets a "thin wrapper" closure that
-- delegates to `engine:__match_rule_conditions_impl(rule, plugin_conf)`.
-- The rule is bound as an upvalue, so each closure is unique-per-rule
-- from the JIT's point of view. Behaviour is identical to the
-- pre-closure baseline; perf change is +1 Lua-call per rule per
-- request, which is negligible noise. The point of stage 1 is to prove
-- the pipeline (load → compile → store → invoke → fallback) and lock
-- in the closure API surface that stages 2-5 specialise.

local _M = {}

-- Stage 1 source template, compiled once at module load time. Each
-- rule instantiates this chunk by calling _stage1_chunk(rule); the
-- chunk's vararg becomes the closure's captured upvalue.
--
-- Stages 2-5 will replace this with per-rule generated source that
-- inlines transforms / variable resolution / operator dispatch / the
-- @rx literal prefilter — one stage at a time, each gated on an empty
-- CRS regression diff.
local _stage1_src = [[
local rule = ...
return function(engine, plugin_conf)
    return engine:__match_rule_conditions_impl(rule, plugin_conf)
end
]]

local _stage1_chunk
do
    local fn, err = load(_stage1_src, "@ka_compile/stage1_wrapper")
    if not fn then
        error("ka_compile: stage 1 template failed to load: " .. tostring(err))
    end
    _stage1_chunk = fn
end

-- Compile a single rule into a closure. Returns:
--   closure : function(engine, plugin_conf) -> matched, matches
--   nil     : compiler refused (shape unsupported, parse error, etc.)
--             — caller leaves rule._compiled unset and the engine falls
--             back to the table-walk for this rule.
function _M.compile_rule(rule, plugin_conf)
    if not rule or not rule.conditions then
        return nil
    end

    local ok, closure_or_err = pcall(_stage1_chunk, rule)
    if not ok then
        if kong and kong.log and kong.log.err then
            kong.log.err("[ka_compile] rule=", tostring(rule.id),
                         " factory error: ", tostring(closure_or_err))
        end
        return nil
    end

    _M.dump_source(rule, plugin_conf, _stage1_src)

    return closure_or_err
end

-- Source-dump helper. Called by compile_rule, once per rule per worker
-- on first compile, gated on plugin_conf.private_debug. One-shot guard
-- via rule._compiled_logged keeps repeat compiles silent.
function _M.dump_source(rule, plugin_conf, src)
    if not plugin_conf or not plugin_conf.private_debug then return end
    if rule._compiled_logged then return end
    rule._compiled_logged = true
    if kong and kong.log and kong.log.debug then
        kong.log.debug("[ka_compile] rule=", rule.id, " source:\n", src)
    end
end

-- Convenience: compile a list of rules in-place, attaching the closure
-- to `rule._compiled` for each successfully compiled rule. Returns
-- (compiled_count, total_count) so callers can log coverage at
-- init_worker / dynamic-rule load time.
function _M.compile_rules(rules, plugin_conf)
    local compiled = 0
    local total = 0
    if type(rules) ~= "table" then return 0, 0 end
    for _, rule in pairs(rules) do
        if type(rule) == "table" then
            total = total + 1
            local closure = _M.compile_rule(rule, plugin_conf)
            if closure then
                rule._compiled = closure
                compiled = compiled + 1
            end
        end
    end
    return compiled, total
end

return _M
