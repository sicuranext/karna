-- ka-unittest/negated_isset_absence.lua
--
-- `isSet` + `negated: true` is the documented way to spell "this variable is
-- absent" (docs/rules.html). Three pieces of logic make it work, and each has a
-- way to go wrong that this file pins:
--
--   1. is_negated_isset()  — recognises the absence form BEFORE the engine's
--      `!op` → `negated` normalization runs. Both the Redis resolver and the
--      absence check need the answer that early. Canonical definition lives in
--      ka_compile.lua; replicated inline here so the test runs in plain Lua
--      with no kong/ngx dependency (same convention as the other snippets).
--
--   2. resolved_absent — "the variable resolved to nothing", captured BEFORE
--      the rule-control removal block in ka_engine. After that block runs,
--      "nothing to match on" is ambiguous: it can mean the request genuinely
--      carries no such variable, or that a ctl:* exclusion deleted the target.
--      Only the first is absence; conflating them makes an exclusion fire a
--      rule it was meant to silence.
--
--   3. Redis is a THIRD state. An unreachable Redis (or the feature switched
--      off) is "unknown", not "absent". Folding it into absence turns a Redis
--      outage into a total outage and inverts the configured `redis_on_error`:
--      an allowlist rule would deny on `skip`/`fail_open` and allow on
--      `fail_closed`, the opposite of both.
--
-- Run from repo root:
--   lua ka-unittest/negated_isset_absence.lua

-- ---------------------------------------------------------------- harness
local fails = 0
local function ok(cond, name)
    if cond then
        print("  ok   - " .. name)
    else
        fails = fails + 1
        print("  FAIL - " .. name)
    end
end

-- ------------------------------------------------- 1. is_negated_isset
-- mirrors ka_compile.is_negated_isset
local function is_negated_isset(condition)
    if type(condition) ~= "table" then return false end
    local op = condition.op
    if type(op) ~= "string" then return false end
    if op == "!isSet" then return true end
    return op == "isSet" and condition.negated == true
end

print("\nis_negated_isset — recognises both accepted input shapes")
ok(is_negated_isset({ op = "isSet", negated = true })  == true,  "canonical {isSet, negated=true}")
ok(is_negated_isset({ op = "!isSet" })                 == true,  "legacy {op=\"!isSet\"}")
ok(is_negated_isset({ op = "isSet" })                  == false, "positive isSet is not absence")
ok(is_negated_isset({ op = "isSet", negated = false }) == false, "explicit negated=false")
ok(is_negated_isset({ op = "rx", negated = true })     == false, "negated rx is not absence")

print("\nis_negated_isset — `negated` is checked with == true, not truthiness")
-- A stray string or number from hand-written JSON must not silently negate.
ok(is_negated_isset({ op = "isSet", negated = "yes" }) == false, "negated=\"yes\" does not negate")
ok(is_negated_isset({ op = "isSet", negated = 1 })     == false, "negated=1 does not negate")
ok(is_negated_isset({})                                == false, "condition with no op")
ok(is_negated_isset(nil)                               == false, "nil condition")
ok(is_negated_isset("isSet")                           == false, "non-table condition")

-- ------------------------------------------------- 2. resolved_absent
-- mirrors the two lines in ka_engine that compute it, plus the Redis override
local function resolved_absent(values, redis_unknown)
    local absent = (values == nil)
                   or (type(values) == "table" and next(values) == nil)
    if redis_unknown then absent = false end
    return absent
end

print("\nresolved_absent — absence vs values present")
ok(resolved_absent(nil, false)             == true,  "nil (no resolver claimed the name)")
ok(resolved_absent({}, false)              == true,  "empty table (resolver found nothing)")
ok(resolved_absent({ ["h:a"] = "v" }, false) == false, "one value present")
ok(resolved_absent({ ["h:a"] = "" }, false)  == false, "empty-string value is still present")

print("\nresolved_absent — a non-table truthy value must not blow up")
-- Guarding with type()=="table" before next() is what keeps a stray scalar from
-- erroring here, the same class as the Set-Cookie pairs-on-string crash.
ok(resolved_absent("scalar", false) == false, "string value treated as present")
ok(resolved_absent(42, false)       == false, "number value treated as present")

print("\nresolved_absent — Redis unknown is not absence")
ok(resolved_absent({}, true)  == false, "empty + redis_unknown → not absent")
ok(resolved_absent(nil, true) == false, "nil + redis_unknown → not absent")

-- ------------------------------------------------- 3. Redis three states
-- mirrors the rerr branch of the Redis isSet resolver in ka_engine
local function redis_isset_on_error(on_error, negated_form)
    if on_error == "fail_closed" then
        return (negated_form and {} or { ["redis.k"] = "1" }), false
    end
    return {}, true
end

-- Would the condition match, given what the resolver produced?
local function condition_matches(values, redis_unknown, negated_form)
    if negated_form then
        return resolved_absent(values, redis_unknown)
    end
    -- the positive form is evaluated inside the per-value loop, which never
    -- runs when there are no values
    return type(values) == "table" and next(values) ~= nil
end

print("\nredis isSet on error — fail_closed denies, whichever way the rule is written")
for _, negated_form in ipairs({ false, true }) do
    local values, unknown = redis_isset_on_error("fail_closed", negated_form)
    ok(condition_matches(values, unknown, negated_form) == true,
       (negated_form and "negated" or "positive") .. " form matches → deny")
end

print("\nredis isSet on error — skip / fail_open never deny")
for _, on_error in ipairs({ "skip", "fail_open" }) do
    for _, negated_form in ipairs({ false, true }) do
        local values, unknown = redis_isset_on_error(on_error, negated_form)
        ok(condition_matches(values, unknown, negated_form) == false,
           on_error .. ", " .. (negated_form and "negated" or "positive") .. " form does not match")
    end
end

print("\nredis isSet on error — the regression this replaces")
-- Before the three-state split the resolver returned present/absent only:
--   rerr → (on_error == "fail_closed") and {k="1"} or {}
-- Under negation that inverted both settings. Assert the old mapping is gone.
local function legacy_redis_isset_on_error(on_error)
    return (on_error == "fail_closed") and { ["redis.k"] = "1" } or {}
end
ok(condition_matches(legacy_redis_isset_on_error("skip"), false, true) == true,
   "legacy mapping DID deny on skip (the bug)")
ok(condition_matches(legacy_redis_isset_on_error("fail_closed"), false, true) == false,
   "legacy mapping DID allow on fail_closed (the bug)")

-- ------------------------------------------------- 4. load-time refusal
-- mirrors refuses_negated_isset_control in ka_compile
local function refuses(rule)
    if not rule.rule_control then return false end
    if type(rule.conditions) ~= "table" then return false end
    for _, condition in ipairs(rule.conditions) do
        if is_negated_isset(condition) then return true end
    end
    return false
end

print("\nload-time refusal — negated isSet on a rule carrying rule_control")
ok(refuses({ rule_control = { {} },
             conditions = { { op = "isSet", negated = true } } }) == true,
   "refused")
ok(refuses({ rule_control = { {} },
             conditions = { { op = "!isSet" } } }) == true,
   "refused, legacy shape")
ok(refuses({ rule_control = { {} },
             conditions = { { op = "rx", value = "x" },
                            { op = "isSet", negated = true } } }) == true,
   "refused when the absence form is any link of the chain")
ok(refuses({ conditions = { { op = "isSet", negated = true } } }) == false,
   "allowed without rule_control — this is the ACL use case")
ok(refuses({ rule_control = { {} },
             conditions = { { op = "isSet" } } }) == false,
   "allowed: positive isSet names something the request carries")
ok(refuses({ rule_control = { {} } }) == false,
   "no conditions at all")

print(string.format("\n%d test(s) failed", fails))
os.exit(fails == 0 and 0 or 1)
