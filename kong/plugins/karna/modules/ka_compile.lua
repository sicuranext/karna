-- ka_compile.lua — Rule-to-closure compiler for the Karna engine.
--
-- Workstream #2 of the perf plan (`bench/notes/rule-to-closure-plan.md`):
-- replace the table-driven dispatch inside ka_engine.__match_rule_conditions
-- with per-rule generated closures so LuaJIT's tracing JIT sees a fixed
-- shape per rule. Operates POST-PARSE on the internal Lua-table rule
-- shape that every rule source already produces — no input format change.
--
-- Stage 0 (this commit): no-op stub. compile_rule() returns nil so the
-- engine's `if rule._compiled then ...` short-circuit never fires and
-- behaviour is identical to baseline. The file exists to lock in the
-- module surface (require path, exported function names) and the
-- private_debug source-dump scaffolding.
--
-- Stages 1-5 fill in the source generator incrementally; each stage is
-- gated on an empty regression diff vs baseline.

local _M = {}

-- Stub: returns nil so __match_rule_conditions falls through to the
-- existing table-walk for every rule. Stage 1 replaces this with a real
-- source generator that mirrors the table-walk 1:1.
--
-- Contract (target shape from stage 1 onward):
--   compile_rule(rule, plugin_conf) -> closure | nil
--   closure signature: function(engine, plugin_conf) -> matched, matches
--   - `engine` is the ka_engine `self` (same as today's match path)
--   - returning nil means "compiler can't handle this rule" → engine
--     uses the table-walk fallback. Permanent coexistence of both paths.
function _M.compile_rule(rule, plugin_conf)
    return nil
end

-- Source-dump helper. Called by compile_rule from stage 1 onward, once
-- per rule per worker on first compile, gated on plugin_conf.private_debug.
-- One-shot guard via rule._compiled_logged keeps repeat compiles silent.
-- Stage 0 is dead code (no caller yet); kept so future stages have a
-- single place to format dumps.
function _M.dump_source(rule, plugin_conf, src)
    if not plugin_conf or not plugin_conf.private_debug then return end
    if rule._compiled_logged then return end
    rule._compiled_logged = true
    if kong and kong.log and kong.log.debug then
        kong.log.debug("[ka_compile] rule=", rule.id, " source:\n", src)
    end
end

return _M
