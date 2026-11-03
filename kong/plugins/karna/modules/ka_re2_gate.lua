-- ka_re2_gate — RE2::Set gating for the @rx fast path (engine_re2_scan spike).
--
-- Direction B of the perf plan (memory karna-re2-spike). Built once per worker
-- at init_worker over the loaded CRS access-phase rules; USED per request only
-- when plugin_conf.engine_re2_scan is true.
--
-- MODEL (sound — see the soundness analysis in memory):
--   * A rule is GATEABLE iff its FIRST condition is a POSITIVE (non-negated)
--     @rx, RE2 accepts the pattern, and EVERY cond1 variable is a resolvable
--     request-value variable. Then: if cond1's @rx matches no request value,
--     cond1 fails => the rule (and its chain) cannot fire => skip it.
--   * Per request we resolve+transform each distinct (variable, transform)
--     spec ONCE and scan the RE2::Set over every resulting value, OR-ing the
--     matched pattern-ids into a global set. A gateable rule is skipped iff its
--     gating pattern's id is NOT in that set. Because the scanned value set is
--     a SUPERSET of any single rule's own (post-rule_control) values, a clear
--     bit proves the pattern matched nothing the rule could see => sound skip.
--     A set bit just means "run the rule's real Lua @rx" (captures, chains,
--     setvar, tx all stay in Lua, in rule-order) — never a detection change.
--   * RE2-rejected patterns and non-resolvable / negated / non-rx cond1 leave
--     the rule UNGATED (always runs) — fail-open, never a silent drop.

local ka_re2     = require "kong.plugins.karna.ka_re2"
local ka_compile = require "kong.plugins.karna.ka_compile"

local _M = {}

-- Coarse gate resolvers for request-value namespaces that
-- ka_compile.compile_variable_resolver doesn't cover (cookie names, XML, files,
-- multipart). Each returns the FULL value set of its broader namespace — a
-- SUPERSET of the specific variable's values, which is sound for gating
-- (scanning extra values can only cause an extra rule-run, never a missed
-- match). This makes those rules UNCONDITIONALLY gateable: on a bodyless/
-- cookieless request the helper returns empty (≈ free); on a body/cookie
-- request the values ARE scanned, so the rule gates on benign body traffic too
-- (fixes the scn09 regression where the earlier "disable on body" approach paid
-- the scan cost without skipping). Helpers take no self -> dot-call; both cache
-- on kong.ctx.plugin so repeated calls are cheap.
-- Body values EXCLUDING uploaded file content (.file_content: keys). The
-- broader namespace these resolvers cover (XML nodes, multipart field/file
-- NAMES, extensions) lives under other keys; the multi-KB file bytes do NOT
-- gate any PL1 @rx (CRS doesn't inspect file content by default — same scope
-- decision as f795a49 keeping file bytes out of ARGS). Scanning them in the
-- pre-pass was pure cost (measured: ~-6% on the 3x10KB multipart scenario).
-- Filtering them keeps gating sound (validated by the CRS regression empty-diff)
-- while removing the file-byte transform+scan tax.
local function body_values_no_file(engine)
    local v = engine.__get_values_request_body(false)
    if type(v) ~= "table" then return v end
    local out = {}
    for k, val in pairs(v) do
        if not string.find(k, ".file_content:", 1, true) then
            out[k] = val
        end
    end
    return out
end

local GATE_EXTRA_RESOLVERS = {
    ["request.cookie.name"]             = function(engine) return engine.__get_values_request_cookie(false) end,
    ["request.body.xml.value"]          = body_values_no_file,
    ["request.body.xml.attr.value"]     = body_values_no_file,
    ["request.file"]                    = body_values_no_file,
    ["request.body.multipart.filename"] = body_values_no_file,
    ["request.body.multipart.name"]     = body_values_no_file,
}

-- Build the gate over a rule list. Returns a gate table, or nil if RE2 is
-- unavailable / no gateable rule exists.
--   gate.handle  : ka_re2 handle (the compiled RE2::Set)
--   gate.gate    : { [rule_id_string] = re2_set_id }  -- gateable rules only
--   gate.specs   : { {variable=, transform=, resolver=} }  -- distinct scan specs
function _M.build(rules)
    if not ka_re2.available() then
        return nil
    end
    if type(rules) ~= "table" then
        return nil
    end

    local patterns   = {}   -- ordered pattern strings handed to RE2::Set::Add
    local rule_at    = {}   -- patterns[i] belongs to rule_at[i] (rule_id string)
    local specs      = {}   -- distinct {variable, transform, resolver}
    local spec_seen  = {}

    -- Diagnostics: WHY rules are excluded from gating (drives resolver coverage).
    local stats = { total = 0, not_rx = 0, negated = 0, multimatch = 0,
                    macro = 0, unresolvable = 0 }
    local unres = {}        -- distinct unresolvable variable string -> rule count

    for _, rule in pairs(rules) do
        if type(rule) == "table" and rule.conditions and rule.conditions[1]
           and rule.id ~= nil then
            stats.total = stats.total + 1
            local c1 = rule.conditions[1]
            local op = c1.op or ""
            local negated = c1.negated == true
            local base = op
            if base:sub(1, 1) == "!" then
                base = base:sub(2)
                negated = true
            end

            -- Exclusions (fail-open => stay on the Lua path):
            --  * non-rx cond1: nothing to gate on.
            --  * negated: a clear RE2 match-set can't prove a !@rx fails.
            --  * multi_match: the engine also matches INTERMEDIATE transform
            --    results; the pre-pass only scans the final value, so gating a
            --    multi_match rule could miss an intermediate match.
            --  * a %{...} macro in the pattern makes the effective regex
            --    dynamic per request, but the RE2::Set is built from the static
            --    string — would gate against the wrong pattern.
            --  * any cond1 variable with no resolver (compile_variable_resolver
            --    nor a coarse GATE_EXTRA_RESOLVER) => the scan can't cover it
            --    => gating would be unsound (might miss a match on that var).
            local has_macro = string.find(c1.value or "", "%{", 1, true) ~= nil
            if base ~= "rx" or type(c1.value) ~= "string" or c1.value == ""
               or type(c1.variables) ~= "table" or #c1.variables == 0 then
                stats.not_rx = stats.not_rx + 1
            elseif negated then
                stats.negated = stats.negated + 1
            elseif c1.multi_match then
                stats.multimatch = stats.multimatch + 1
            elseif has_macro then
                stats.macro = stats.macro + 1
            else
                local var_specs  = {}
                local gateable   = true
                for _, v in pairs(c1.variables) do
                    local resolver = ka_compile.compile_variable_resolver(v)
                                     or GATE_EXTRA_RESOLVERS[v]
                    if resolver ~= nil then
                        var_specs[#var_specs + 1] = {
                            variable  = v,
                            transform = c1.transform or {},
                            resolver  = resolver,
                        }
                    else
                        gateable = false
                        unres[v] = (unres[v] or 0) + 1
                    end
                end

                if gateable then
                    patterns[#patterns + 1] = c1.value
                    rule_at[#patterns]      = tostring(rule.id)
                    for _, sp in ipairs(var_specs) do
                        local key = sp.variable .. "\1"
                                    .. table.concat(sp.transform, ",")
                        if not spec_seen[key] then
                            spec_seen[key] = true
                            specs[#specs + 1] = sp
                        end
                    end
                else
                    stats.unresolvable = stats.unresolvable + 1
                end
            end
        end
    end

    if #patterns == 0 then
        return nil
    end

    local handle, err, id_map, rejected = ka_re2.build(patterns, true)
    if not handle then
        if kong and kong.log then
            kong.log.err("[ka_re2_gate] RE2::Set build failed: ", tostring(err))
        end
        return nil
    end

    -- Map rule-id -> RE2 set-id; patterns RE2 rejected (id_map[i] == false)
    -- leave their rule UNGATED (no entry) -> it stays on the Lua @rx path.
    local gate = {}
    local gateable = 0
    -- One single-pattern Set per accepted pattern, for the sharded scan (see
    -- scan_sharded). A shard that fails to build is recorded as `false`: the
    -- sharded scan then reports its id as matched (= run the rule), never as
    -- a silent skip.
    local shards = {}
    for i = 1, #patterns do
        local set_id = id_map[i]
        if set_id ~= false then
            gate[rule_at[i]] = set_id
            gateable = gateable + 1
            local sh = ka_re2.build({ patterns[i] }, true)
            shards[#shards + 1] = { id = set_id, handle = sh or false }
        end
    end

    -- Build a compact "unresolvable variable -> count" diagnostic string.
    local unres_list = {}
    for v, c in pairs(unres) do unres_list[#unres_list + 1] = v .. "(" .. c .. ")" end
    table.sort(unres_list)

    local gate_obj = {
        handle     = handle,
        shards     = shards,
        gate       = gate,
        specs      = specs,
        n_patterns = handle.n_patterns,
        gateable   = gateable,
        rejected   = rejected and #rejected or 0,
        stats      = stats,
        unres      = table.concat(unres_list, " "),
    }
    -- Self-contained run closure so the engine can invoke the pre-pass via
    -- `self._re2_gate.run(engine)` WITHOUT requiring this module (avoids any
    -- load-order coupling in ka_engine).
    gate_obj.run = function(engine)
        return _M.scan(gate_obj, engine)
    end
    return gate_obj
end

-- Sharded scan: the combined Set is cheap on ordinary text (its lazily built
-- DFA states are reused across values and requests) but on high-entropy input
-- almost every byte reaches a DFA state that does not exist yet, and building a
-- state of the ~200-pattern program costs tens of microseconds per byte, paid
-- again for every transform chain the value is scanned under.
-- One Set per pattern keeps every DFA small: ~0.7 us per byte on the same
-- input, but a fixed ~20 us per value (one FFI call per pattern), which is
-- why short values stay on the combined Set while it is fast.
--   LONG_VALUE     : a value longer than this always goes to the shards, so
--                    one combined scan costs at most ~25 ms.
--   COMBINED_BUDGET: seconds of combined-Set scanning per request above what
--                    warm-cache input costs (ALLOW_PER_VALUE + ALLOW_PER_BYTE
--                    for each value scanned); past it every remaining value
--                    goes to the shards. Only the scan calls are timed, not
--                    parsing or transforms. Measuring the excess instead of
--                    the total keeps a large benign body (thousands of
--                    values, each well under a microsecond) on the combined
--                    Set, while new-state input trips it within a few values.
--                    Benign values padded in to earn allowance buy at most
--                    ALLOW_PER_BYTE per byte: under the default arg limits
--                    that is a few hundred ms per request at worst.
-- Both paths scan the same patterns, so the matched set and every gating
-- decision are identical; only the cost changes.
local LONG_VALUE      = 1024
local COMBINED_BUDGET = 0.003
local ALLOW_PER_VALUE = 2e-6
local ALLOW_PER_BYTE  = 2e-8

_M.LONG_VALUE      = LONG_VALUE
_M.COMBINED_BUDGET = COMBINED_BUDGET

-- CLOCK_MONOTONIC through the vDSO: ~10 ns a read, against ~180 ns for
-- os.clock(), so every combined scan can be timed. Kong (and other modules)
-- may already have declared clock_gettime / struct timespec, so each
-- declaration is attempted on its own and the result is probed once; any
-- failure keeps os.clock.
local now = os.clock
do
    local ok_ffi, ffi = pcall(require, "ffi")
    if ok_ffi and ffi.os == "Linux" then
        pcall(ffi.cdef, "struct timespec { long tv_sec; long tv_nsec; };")
        pcall(ffi.cdef, "int clock_gettime(int clk_id, struct timespec *tp);")
        local ok_ts, ts = pcall(ffi.new, "struct timespec")
        if ok_ts then
            local C = ffi.C
            local function mono()
                C.clock_gettime(1, ts)  -- CLOCK_MONOTONIC
                return tonumber(ts.tv_sec) + tonumber(ts.tv_nsec) * 1e-9
            end
            if pcall(mono) then now = mono end
        end
    end
end

local function scan_sharded(shards, matched, v)
    for i = 1, #shards do
        local sh = shards[i]
        local id = sh.id
        if not matched[id] then
            if not sh.handle or ka_re2.scan(sh.handle, v) ~= 0 then
                matched[id] = true
            end
        end
    end
end

local function scan_combined(handle, matched, v)
    local n = ka_re2.scan(handle, v)
    if n > 0 then
        local lim = n < handle.max_ids and n or handle.max_ids
        for k = 0, lim - 1 do
            matched[ka_re2.id_at(handle, k)] = true
        end
    end
end

-- Per-request pre-pass: resolve+transform every distinct spec's values, scan
-- the RE2::Set, return the set { [re2_set_id] = true } of all matched patterns.
-- `engine` is the ka_engine instance (for resolvers + __apply_transformation).
function _M.scan(gate, engine)
    local handle = gate.handle
    local shards = gate.shards
    local matched = {}
    -- combined-Set accounting (see LONG_VALUE / COMBINED_BUDGET above)
    local sharded = false
    local excess  = 0
    local resolved = {}          -- variable string -> values table (resolve once)
    local scanned = {}           -- post-transform value string -> true (scan once)
    local dummy_rule = {}        -- resolvers take (engine, rule); no rule_control
                                 -- => full namespace = a superset (sound)

    -- Transform-cache hoist: resolve the per-request transform cache ONCE for
    -- the whole pre-pass and thread it into __apply_transformation, instead of
    -- a kong.ctx.plugin ctx-__index hit on every (spec × value × chain-step)
    -- call. Same table the engine would lazily create otherwise.
    local txc = kong.ctx.plugin.ka_tx_cache
    if txc == nil then txc = {}; kong.ctx.plugin.ka_tx_cache = txc end

    for _, sp in ipairs(gate.specs) do
        local values = resolved[sp.variable]
        if values == nil then
            local ok, v = pcall(sp.resolver, engine, dummy_rule)
            values = (ok and v) or false
            resolved[sp.variable] = values
        end

        if values then
            local chain = sp.transform
            local nchain = #chain
            for _, raw in pairs(values) do
                if type(raw) == "string" then
                    local v = raw
                    for ci = 1, nchain do
                        if type(v) == "string" then
                            v = engine:__apply_transformation(chain[ci], v, txc)
                        end
                    end
                    -- Scan each DISTINCT post-transform value once. RE2 match is
                    -- a pure function of the string, so the same value produced
                    -- by different (variable, chain) specs need not re-scan —
                    -- this collapses the cross-spec redundancy that would
                    -- otherwise blow up on body-bearing requests (many body
                    -- vars share __get_values_request_body + the same chain).
                    if type(v) == "string" and not scanned[v] then
                        scanned[v] = true
                        if shards and (sharded or #v > LONG_VALUE) then
                            scan_sharded(shards, matched, v)
                        else
                            local t0 = now()
                            scan_combined(handle, matched, v)
                            excess = excess + (now() - t0)
                                    - ALLOW_PER_VALUE - #v * ALLOW_PER_BYTE
                            if shards and excess > COMBINED_BUDGET then
                                sharded = true
                            end
                        end
                    end
                end
            end
        end
    end

    return matched
end

return _M
