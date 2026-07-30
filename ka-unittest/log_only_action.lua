-- ka-unittest/log_only_action.lua
--
-- Guards the `log_only` action — the opt-in that makes a NON-TERMINAL match
-- reach the audit log as a real entry in `matches[]` (v2) / `messages[]` (v1).
--
-- The regression being pinned: `loop_rules` returns only the first *terminal*
-- rule, so before `log_only` a `pass`+`log` rule fired its side effects and then
-- vanished. Measured on a live stack: with `auditlog_only_on_match = true` such a
-- rule produced NO audit entry at all, in either format; with it `false` it
-- produced an entry on every request whose `matches[]` was empty. The phase was
-- never the problem — a terminal header_filter rule logged fine — non-terminality
-- was.
--
-- Three properties are load-bearing and tested here:
--   1. the flag is what decides. A non-terminal match WITHOUT `log_only` must
--      stay unrecorded, or the CRS `pass` helper rules (setvar counters, ctl
--      gates, chain scaffolding) flood the audit log. They cannot be filtered by
--      `log`, because `load_rules` sets `rule.log = true` on the whole CRS pack.
--   2. a recorded `log_only` match makes `loggable_matches` non-empty, which is
--      what satisfies `auditlog_only_on_match` — the reason the rule is visible
--      at all without logging every request.
--   3. the audit-log action label is `log` (not block / detect / sanitized).
--
-- SUT is replicated inline (same convention as rule_control_runtime.lua,
-- rule_overrides.lua, wordpress_target_exclusion.lua) so the test needs no
-- kong/ngx globals. KEEP IN SYNC with:
--   kong/plugins/karna/modules/ka_engine.lua  the terminal check + log_only
--                                             insert in loop_rules
--   kong/plugins/karna/modules/ka_utils.lua   the action_label ladder
--   kong/plugins/karna/handler.lua            the loggable_matches filter
--
-- Run from repo root:
--   lua    ka-unittest/log_only_action.lua
--   luajit ka-unittest/log_only_action.lua

local fails = 0
local function ok(cond, name)
    if cond then print("  ok  - " .. name)
    else print("  FAIL- " .. name); fails = fails + 1 end
end

-- ============================================================
-- SUT — copy from ka_engine.lua:loop_rules, the post-match tail.
-- Returns "terminal" when the loop would stop, "recorded" when the match was
-- filed for the audit log, or "dropped" when it fired side effects and vanished.
-- `collected` stands in for kong.ctx.plugin.ka_matched_rules.
-- ============================================================
local function handle_match(collected, rule, matches)
    local action = rule.action or {}
    local is_terminal = action.fixed_response
                     or action.fix_matched_parts
                     or action.rate_limit
                     or action.mcp_event_action
    if is_terminal then
        return "terminal"
    end
    if action.log_only == true and collected then
        collected[#collected + 1] = {
            rule      = rule,
            part      = matches,
            sanitized = false,
        }
        return "recorded"
    end
    return "dropped"
end

-- SUT — copy from ka_utils.lua:get_auditlog_v2, the action_label ladder.
local function action_label(matched, engine_blocking_mode, detection_only)
    local rule = matched.rule
    local label = "log"
    if matched.sanitized then
        label = "sanitized"
    elseif matched.rate_limited then
        label = "rate_limited"
    elseif rule.action and rule.action.fixed_response then
        if engine_blocking_mode and not detection_only then
            label = "block"
        else
            label = "detect"
        end
    end
    return label
end

-- SUT — copy from handler.lua:log, the loggable_matches filter.
local function loggable(collected)
    local out = {}
    for _, m in ipairs(collected) do
        if m.rule.log then out[#out + 1] = m end
    end
    return out
end

-- `auditlog_only_on_match` skips the write when there is nothing to say.
local function would_write(collected, only_on_match, has_external)
    if only_on_match and #loggable(collected) == 0 and not has_external then
        return false
    end
    return true
end

local MATCHES = { { matched_on = "response.header.value:x-app-verdict",
                    matched_value = "deny,ip-reputation" } }

-- The shape this action exists for: a header_filter rule reacting to a verdict
-- the upstream put in a response header, whose only action is set_log_fields.
local function verdict_rule(log_only)
    local action = {
        set_log_fields = {
            { name = "app_verdict",      value = "Upstream denied the request" },
            { name = "app_verdict_code", value = "%{response.header.value:x-app-verdict}" },
        },
    }
    if log_only then action.log_only = true end
    return {
        id = "9001", phase = "header_filter", log = true,
        message = "Upstream denied the request",
        tags = { "observability", "upstream-verdict" },
        action = action,
    }
end

-- ============================================================
print("- log_only records a non-terminal match; without it the match is dropped")
-- ============================================================
local collected = {}
ok(handle_match(collected, verdict_rule(true), MATCHES) == "recorded",
   "with log_only → recorded")
ok(#collected == 1, "one entry filed")
ok(collected[1].rule.id == "9001", "the rule itself is carried (id survives)")
ok(collected[1].part == MATCHES, "matched parts carried (v1 needs them for `data`)")
ok(collected[1].sanitized == false, "not marked sanitized")

collected = {}
ok(handle_match(collected, verdict_rule(false), MATCHES) == "dropped",
   "without log_only → dropped (CRS pass helpers stay out of the audit log)")
ok(#collected == 0, "nothing filed")

-- A truthy-but-not-true value must not opt in: the flag is checked with `== true`
-- so a stray string from hand-written JSON can't silently enable it.
collected = {}
local sloppy = verdict_rule(false); sloppy.action.log_only = "yes"
ok(handle_match(collected, sloppy, MATCHES) == "dropped",
   "log_only = \"yes\" does NOT opt in (strict == true)")

-- ============================================================
print("")
print("- log_only is non-terminal: it never stops the rule loop")
-- ============================================================
collected = {}
ok(handle_match(collected, verdict_rule(true), MATCHES) == "recorded",
   "a log_only match does not report terminal")

-- A rule carrying both is terminal; log_only is then redundant, and the terminal
-- path records it anyway (handler.lua does that).
collected = {}
local both = verdict_rule(true)
both.action.fixed_response = { status_code = 403 }
ok(handle_match(collected, both, MATCHES) == "terminal",
   "log_only + fixed_response → terminal wins")
ok(#collected == 0, "the terminal path records it, not this one (no double entry)")

-- ============================================================
print("")
print("- a log_only match satisfies auditlog_only_on_match")
-- ============================================================
collected = {}
handle_match(collected, verdict_rule(true), MATCHES)
ok(would_write(collected, true, false),
   "only_on_match=true + a log_only match → the entry IS written")

collected = {}
handle_match(collected, verdict_rule(false), MATCHES)
ok(not would_write(collected, true, false),
   "only_on_match=true, no log_only → nothing written (the old behaviour)")
ok(would_write(collected, false, false),
   "only_on_match=false → written regardless, as before")

-- `log: false` on the rule still suppresses it: log_only decides whether the
-- match is COLLECTED, `log` whether it is LOGGED. Two independent knobs.
collected = {}
local quiet = verdict_rule(true); quiet.log = false
handle_match(collected, quiet, MATCHES)
ok(#collected == 1, "collected")
ok(#loggable(collected) == 0, "but filtered out by log=false")
ok(not would_write(collected, true, false), "so no entry is written")

-- ============================================================
print("")
print("- the audit log labels it `log`, not block / detect / sanitized")
-- ============================================================
collected = {}
handle_match(collected, verdict_rule(true), MATCHES)
ok(action_label(collected[1], true, false) == "log",
   "blocking service → still `log` (nothing was blocked)")
ok(action_label(collected[1], false, false) == "log",
   "detection service → `log`")

-- Contrast: the same ladder on a terminal rule.
local blocked = { rule = { action = { fixed_response = { status_code = 403 } } }, sanitized = false }
ok(action_label(blocked, true, false) == "block", "fixed_response + blocking → block")
ok(action_label(blocked, true, true) == "detect", "fixed_response + DetectionOnly → detect")

-- ============================================================
print("")
print("- several log_only rules on one request all land")
-- ============================================================
-- The loop does not stop on a log_only match, so every matching one is recorded.
collected = {}
local r1 = verdict_rule(true)
local r2 = verdict_rule(true); r2.id = "9002"; r2.message = "Upstream flagged the response"
handle_match(collected, r1, MATCHES)
handle_match(collected, r2, MATCHES)
ok(#collected == 2, "both recorded")
ok(collected[1].rule.id == "9001" and collected[2].rule.id == "9002",
   "in match order (v1 takes the last, v2 keeps them all)")

-- ============================================================
print("")
print("- no ka_matched_rules table (access phase was skipped) → no crash")
-- ============================================================
-- ignore_from_local_ips / response_from_cache return before the store exists,
-- and header_filter still runs.
ok(handle_match(nil, verdict_rule(true), MATCHES) == "dropped",
   "nil collector is tolerated, match is simply not recorded")

print(string.format("\n%d test(s) failed", fails))
os.exit(fails == 0 and 0 or 1)
