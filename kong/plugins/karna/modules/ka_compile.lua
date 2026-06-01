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

-- Engine-internal fields attached to rule tables by ka_compile. Any
-- code path that JSON-encodes a rule (private_debug response body,
-- audit log enrichment, …) must skip these — `_compiled` is a Lua
-- function and `cjson.encode` rejects functions outright.
local ka_re2 = require "kong.plugins.karna.ka_re2"

local _RULE_INTERNAL_FIELDS = {
    _compiled        = true,
    _compiled_logged = true,
    _needs_body      = true,  -- precomputed "rule cannot fire without a request body" flag
}

local _CONDITION_INTERNAL_FIELDS = {
    _ka_pf_lits = true,  -- @rx literal prefilter memo (engine-managed)
    _tchain     = true,  -- precompiled transform chain closure (stage 2)
    _resolvers  = true,  -- precompiled variable resolver array (stage 3)
    _re2_re     = true,  -- precompiled RE2 single-pattern @rx handle (FFI cdata)
}

-- Return a 2-level filtered copy of a rule table with engine-internal
-- fields stripped at BOTH the rule level (`_compiled`, `_compiled_logged`)
-- AND the per-condition level (`_ka_pf_lits`, `_tchain`). Safe for
-- cjson.encode and any caller that wants a "publishable" view of the
-- rule (response body for private_debug, audit log payload, MCP rule
-- echoes). The condition-level filter is required because the encoder
-- recurses into nested tables — a function field on a condition fails
-- the encode just as surely as one on the rule.
function _M.public_view(rule)
    if type(rule) ~= "table" then return rule end
    local out = {}
    for k, v in pairs(rule) do
        if _RULE_INTERNAL_FIELDS[k] then
            -- skip
        elseif k == "conditions" and type(v) == "table" then
            local conds = {}
            for i, c in ipairs(v) do
                if type(c) == "table" then
                    local cc = {}
                    for ck, cv in pairs(c) do
                        if not _CONDITION_INTERNAL_FIELDS[ck] then
                            cc[ck] = cv
                        end
                    end
                    conds[i] = cc
                else
                    conds[i] = c
                end
            end
            out[k] = conds
        else
            out[k] = v
        end
    end
    return out
end

-- Stage 2: precompiled per-condition transform chain.
--
-- The engine's table-walk applies the chain via a runtime `for tfunc in
-- condition.transform` loop at `ka_engine.lua:2367-2378`. Generating a
-- straight-line function with each call unrolled removes the per-value
-- iteration overhead and gives LuaJIT a fixed-shape callsite. The
-- function still calls `engine:__apply_transformation(tfunc, value)`
-- per step — value-level caching stays where it is. Stages 3-5 will
-- replace those internal calls with the specific transform helpers.
--
-- Semantics preserved verbatim from the loop:
--   - Each step is guarded by `type(value) == "string"`: if a transform
--     returns a non-string (e.g. `t:length` → number), subsequent steps
--     skip without erroring.
--   - When `want_multi` is true (condition.multi_match), each
--     successful step appends its result to the multi-match list. The
--     list returned is `nil` when `want_multi` is false (the caller
--     fills it with `{}` for symmetry).
--
-- Returns the closure or nil for an empty/nil transform list (the
-- caller leaves condition._tchain unset and the engine takes the
-- fallback loop, which is a 0-iteration no-op in that case anyway).
function _M.compile_transform_chain(transforms)
    if type(transforms) ~= "table" or #transforms == 0 then
        return nil
    end

    -- `txc` (engine_tx_cache_hoist): the caller passes the already-resolved
    -- per-request transform cache so __apply_transformation skips its
    -- kong.ctx.plugin ctx-__index lookup on every step. Threaded straight
    -- through; nil when the flag is off (engine resolves it per-call).
    local lines = {
        "return function(engine, value, want_multi, txc)",
        "    local mt = want_multi and {} or nil",
    }
    for _, tfunc in ipairs(transforms) do
        local quoted = string.format("%q", tostring(tfunc))
        lines[#lines + 1] = "    if type(value) == \"string\" then"
        lines[#lines + 1] = "        value = engine:__apply_transformation("
                            .. quoted .. ", value, txc)"
        lines[#lines + 1] = "        if mt then mt[#mt + 1] = value end"
        lines[#lines + 1] = "    end"
    end
    lines[#lines + 1] = "    return value, mt"
    lines[#lines + 1] = "end"

    local src = table.concat(lines, "\n")
    local chunk, err = load(src, "@ka_compile/tchain")
    if not chunk then
        if kong and kong.log and kong.log.err then
            kong.log.err("[ka_compile] tchain compile error: ", err)
        end
        return nil
    end
    return chunk()
end

-- Stage 3: precompiled per-variable resolver.
--
-- The engine's variable dispatcher in `__match_rule_conditions_impl`
-- (~lines 1875-2305) is a chain of `if string_find(variable, "^...")
-- elseif variable == "..." ...` branches that runs for every (rule,
-- condition, variable) tuple at request time. For most rules the
-- correct branch is reached only after walking past 5-10 unmatched
-- patterns. Stage 3 picks the branch ONCE at init_worker — for each
-- variable string in `condition.variables`, emit a closure that
-- directly calls the right helper (e.g. `engine:__get_values_request_args`)
-- with any pattern-derived arguments (arg names, header names, tx
-- variable names) pre-extracted as upvalues.
--
-- The closure signature is `function(engine, rule) -> values, err`.
-- Returning nil from compile_variable_resolver leaves the slot empty
-- and the engine falls back to the dispatcher chain for that variable.
-- That keeps the engine's behaviour authoritative for any variable
-- shape we haven't whitelisted here.
--
-- Variables that depend on per-condition context (`matched.value`,
-- `group:<N>`, `group_rx:<pattern>`) are intentionally NOT precompiled
-- — they need access to the `matches` / `rx_matched_values_cross_conditions`
-- locals inside the condition loop, which the resolver can't see.
function _M.compile_variable_resolver(variable)
    if type(variable) ~= "string" or variable == "" then
        return nil
    end

    -- tx:<name> — ModSec TX:VAR lookup from kong.ctx.plugin.tx_variables.
    if string.sub(variable, 1, 3) == "tx:" then
        local tx_name = string.sub(variable, 4)
        return function(engine, rule)
            if kong.ctx.plugin.tx_variables
               and kong.ctx.plugin.tx_variables[tx_name] ~= nil then
                return { [variable] = tostring(kong.ctx.plugin.tx_variables[tx_name]) }
            end
            return nil
        end
    end

    -- request.arg.value (canonical ARGS — query + body urlencoded merge).
    if variable == "request.arg.value" then
        return function(engine, rule)
            return engine:__get_values_request_args(false, rule.rule_control)
        end
    end

    -- request.arg.name — ARGS_NAMES (every arg key name).
    if variable == "request.arg.name" then
        return function(engine, rule)
            local all_values, all_err = engine:__get_values_request_args(false, rule.rule_control)
            if all_values then
                local out = {}
                for k, v in pairs(all_values) do
                    if string.find(k, "%.name:", 1, false) then
                        out[k] = v
                    end
                end
                return out, all_err
            end
            return nil, all_err
        end
    end

    -- request.arg.value:<name> — single ARGS entry by name. Suffix
    -- patterns precomputed; the closure only iterates and filters.
    if string.sub(variable, 1, 19) == "request.arg.value:" then
        local arg_name = string.sub(variable, 19)
        -- The leading `:` in the substring boundary: variable is
        -- "request.arg.value:<name>" (no `:` index 19 because string
        -- indexes are 1-based — `request.arg.value:` is 18 chars).
        -- Recompute precisely:
        arg_name = string.match(variable, "^request%.arg%.value%:(.*)")
        if arg_name == nil then return nil end
        local suffix1 = "%." .. arg_name .. "$"
        local suffix2 = ":" .. arg_name .. "$"
        return function(engine, rule)
            local all_values, all_err = engine:__get_values_request_args(false, rule.rule_control)
            if all_values then
                local out = {}
                for k, v in pairs(all_values) do
                    if string.find(k, suffix1) or string.find(k, suffix2) then
                        out[k] = v
                    end
                end
                return out, all_err
            end
            return nil, all_err
        end
    end

    -- request.query.value / request.query.name / request.query.value:<name>
    if variable == "request.query.value" then
        return function(engine, rule)
            local qvals = engine.__get_values_request_query_value(false)
            if qvals then
                local out = {}
                for k, v in pairs(qvals) do
                    if string.find(k, "%.value:", 1, false) then
                        out[k] = v
                    end
                end
                if next(out) ~= nil then return out end
            end
            return nil
        end
    end
    if variable == "request.query.name" then
        return function(engine, rule)
            local qvals = engine.__get_values_request_query_value(false)
            if qvals then
                local out = {}
                for k, v in pairs(qvals) do
                    if string.find(k, "%.name:", 1, false) then
                        out[k] = v
                    end
                end
                if next(out) ~= nil then return out end
            end
            return nil
        end
    end
    if string.find(variable, "^request%.query%.value%:") then
        local arg_name = string.match(variable, "^request%.query%.value%:(.*)")
        local suffix = ":" .. arg_name .. "$"
        return function(engine, rule)
            local qvals = engine.__get_values_request_query_value(false)
            if qvals then
                local out = {}
                for k, v in pairs(qvals) do
                    if string.find(k, suffix) then
                        out[k] = v
                    end
                end
                if next(out) ~= nil then return out end
            end
            return nil
        end
    end

    -- request.raw_path
    if variable == "request.raw_path" then
        return function(engine, rule)
            return engine.__get_values_request_raw_path()
        end
    end

    -- request.path_with_query — kong.request live, init_worker-guarded.
    if variable == "request.path_with_query" then
        return function(engine, rule)
            if ngx.get_phase() ~= "init_worker" then
                return { ["request.path_with_query"] = tostring(kong.request.get_path_with_query()) }
            end
            return nil
        end
    end

    -- request.method
    if variable == "request.method" then
        return function(engine, rule)
            if ngx.get_phase() ~= "init_worker" then
                return { ["request.method"] = tostring(kong.request.get_method()) }
            end
            return nil
        end
    end

    -- request.http_version — emitted in canonical "HTTP/X.Y" shape
    if variable == "request.http_version" then
        return function(engine, rule)
            if ngx.get_phase() ~= "init_worker" then
                local v = kong.request.get_http_version()
                if v then
                    return { ["request.http_version"] = "HTTP/" .. tostring(v) }
                end
            end
            return nil
        end
    end

    -- request.line — full HTTP request line ("METHOD /uri HTTP/x.y").
    if variable == "request.line" then
        return function(engine, rule)
            if ngx.get_phase() ~= "init_worker" then
                local line = ngx.var.request
                if line then
                    return { ["request.line"] = tostring(line) }
                end
            end
            return nil
        end
    end

    -- request.basename
    if variable == "request.basename" then
        return function(engine, rule)
            return engine.__get_values_basename()
        end
    end

    -- request.raw_query
    if variable == "request.raw_query" then
        return function(engine, rule)
            return engine.__get_values_request_raw_query()
        end
    end

    -- request.header.value / request.header.value:<name>
    if variable == "request.header.value" then
        return function(engine, rule)
            return engine.__get_values_request_headers_all()
        end
    end
    if string.find(variable, "^request%.header%.value:") then
        return function(engine, rule)
            return engine.__get_values_request_header(variable)
        end
    end

    -- request.cookie.value
    if variable == "request.cookie.value" then
        return function(engine, rule)
            return engine:__get_values_request_cookie(false)
        end
    end

    -- Scalar body variables — request.body, request.body.length, request.body.processor.
    if variable == "request.body"
       or variable == "request.body.length"
       or variable == "request.body.processor" then
        return function(engine, rule)
            local scalars = engine.__get_values_request_body_scalars()
            if scalars and scalars[variable] ~= nil then
                return { [variable] = tostring(scalars[variable]) }
            end
            return nil
        end
    end

    return nil
end

-- Walk a rule's conditions and attach precompiled artifacts:
--   condition._tchain    — transform chain closure (stage 2)
--   condition._resolvers — parallel array to condition.variables; each
--                          slot is either a resolver closure (stage 3)
--                          or nil (engine falls back to dispatcher).
-- Init-worker / dynamic-rule-load mutation only — same policy as
-- `condition._ka_pf_lits` (see comment block at ka_engine.lua:1782).
-- A variable is "body-only" when it resolves to an EMPTY values-table
-- whenever the request carries no body. Such a variable is produced solely
-- by the request-body parser (multipart / json / xml / urlencoded body, or
-- uploaded files). Query args, headers, cookies, URI etc. are explicitly NOT
-- body-only (ARGS in particular mixes query + body, so it can match on the
-- query alone). Count / size / processor variables are excluded because they
-- CAN match on an absent body (e.g. `&FILES @eq 0`, `REQBODY_PROCESSOR`
-- derived from Content-Type) — treating them as body-only would wrongly skip
-- a rule that fires precisely on "no body present".
local function is_body_only_var(v)
    if type(v) ~= "string" then return false end
    if v == "request.body.processor"
       or v:find("%.count$")
       or v:find("%.combined_size$")
       or v:find("%.length$") then
        return false
    end
    if v == "request.body" or v == "request.body.value" then return true end
    return v:find("^request%.body%.json")      == 1
        or v:find("^request%.body%.xml")       == 1
        or v:find("^request%.body%.urlencode") == 1
        or v:find("^request%.body%.multipart") == 1
        or v:find("^request%.file")            == 1
end

-- Ops that DON'T fail-closed on an empty values-table: `unconditionalMatch`
-- always fires; `isSet` is a presence test (and its negation fires on
-- absence). A condition using one of these — even on a body-only variable —
-- could still fire without a body, so it must NOT contribute to `_needs_body`.
local _NON_BODY_GATING_OPS = {
    unconditionalMatch = true,
    isSet              = true,
}

-- A condition is "body-requiring" when, with no request body present, it
-- provably CANNOT match: it must be a positive (non-negated) per-value op,
-- and EVERY one of its variables must be body-only. A positive per-value op
-- iterates the variable's values; on an empty values-table it runs zero
-- iterations -> no match. A negated condition is the opposite — it fires on
-- the empty set — so it never counts. Conservative by construction: when in
-- doubt the answer is `false` (rule keeps running), so the optimisation can
-- only ever skip rules that were guaranteed not to fire.
local function condition_requires_body(condition)
    local op = condition.op
    if type(op) ~= "string" then return false end
    if condition.negated == true or op:sub(1, 1) == "!" then return false end
    local base = op:sub(1, 1) == "!" and op:sub(2) or op
    if _NON_BODY_GATING_OPS[base] then return false end
    local vars = condition.variables
    if type(vars) ~= "table" then return false end
    local nvars = 0
    for _, v in pairs(vars) do
        nvars = nvars + 1
        if not is_body_only_var(v) then return false end
    end
    return nvars > 0
end

local function compile_rule_conditions(rule)
    if not rule.conditions then return end
    local needs_body = false
    for _, condition in ipairs(rule.conditions) do
        if type(condition) == "table" then
            if not needs_body and condition_requires_body(condition) then
                needs_body = true
            end
            if condition.transform then
                condition._tchain = _M.compile_transform_chain(condition.transform)
            end
            -- Precompile the @rx pattern into a single-pattern RE2 matcher used
            -- when engine_re2_match is on (linear-time / ReDoS-safe). re_compile
            -- returns nil for patterns RE2 rejects (lookaround / backref) -> the
            -- engine keeps that condition on ngx.re.match (fallback, never a
            -- silent drop). Covers both positive and negated @rx.
            local cop = condition.op
            if type(cop) == "string" then
                local cbase = cop:sub(1, 1) == "!" and cop:sub(2) or cop
                if cbase == "rx" and type(condition.value) == "string"
                   and condition.value ~= "" then
                    condition._re2_re = ka_re2.re_compile(condition.value, true)
                end
            end
            if type(condition.variables) == "table" and #condition.variables > 0 then
                local resolvers = {}
                local any = false
                for i, var in ipairs(condition.variables) do
                    local fn = _M.compile_variable_resolver(var)
                    resolvers[i] = fn
                    if fn ~= nil then any = true end
                end
                if any then condition._resolvers = resolvers end
            end
        end
    end
    rule._needs_body = needs_body
end

-- Convenience: compile a list of rules in-place, attaching the closure
-- to `rule._compiled` for each successfully compiled rule. Also wires
-- per-condition precompiled artifacts (transform chain — stage 2).
-- Returns (compiled_count, total_count) so callers can log coverage at
-- init_worker / dynamic-rule load time.
function _M.compile_rules(rules, plugin_conf)
    local compiled = 0
    local total = 0
    if type(rules) ~= "table" then return 0, 0 end
    for _, rule in pairs(rules) do
        if type(rule) == "table" then
            total = total + 1
            compile_rule_conditions(rule)
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
