-- ka-unittest/op_negation_normalization.lua
--
-- Verify the op normalization shim that lives at the top of
-- ka_engine.__match_rule_conditions. Two acceptable input shapes:
--
--   1. Canonical (Karna-emitted):  { op = "rx",  negated = true|false }
--   2. Legacy   (ModSec-emitted):  { op = "!rx" }  (also  "!isSet",
--                                  "!eq", etc.)
--
-- Both must normalize to the same `(op_base, negated)` pair. The shim
-- is exactly 7 lines in ka_engine.lua; we replicate it inline (same
-- pattern as the other unit tests) so the test runs in plain Lua with
-- zero kong/ngx dependencies.
--
-- Run from repo root:
--   lua ka-unittest/op_negation_normalization.lua

local function normalize(condition)
    local op_base = condition.op or ""
    local negated = condition.negated == true
    if op_base:sub(1, 1) == "!" then
        op_base = op_base:sub(2)
        negated = true
    end
    return op_base, negated
end

local fails = 0
local function ok(cond, name)
    if cond then
        print("  ok  - " .. name)
    else
        print("  FAIL- " .. name)
        fails = fails + 1
    end
end

local function equal_pair(got_op, got_negated, want_op, want_negated)
    return got_op == want_op and got_negated == want_negated
end

-- ============================================================
-- canonical form
-- ============================================================
print("- canonical form, negated=false")
local op, neg = normalize({ op = "rx", negated = false })
ok(equal_pair(op, neg, "rx", false), "{op=rx, negated=false} → (rx, false)")

print("- canonical form, negated=true")
op, neg = normalize({ op = "rx", negated = true })
ok(equal_pair(op, neg, "rx", true), "{op=rx, negated=true} → (rx, true)")

print("- canonical form, negated absent → false")
op, neg = normalize({ op = "rx" })
ok(equal_pair(op, neg, "rx", false), "{op=rx} → (rx, false)")

print("- canonical form, negated=nil (explicit) → false")
op, neg = normalize({ op = "rx", negated = nil })
ok(equal_pair(op, neg, "rx", false), "{op=rx, negated=nil} → (rx, false)")

-- A truthy-but-not-true value (string "true", number 1) must NOT
-- count as negated — the field is strictly boolean by contract. This
-- guards against the JSON-decoder converting a stray "true" string
-- into something that bypasses the strict `== true` check.
print("- canonical form, negated truthy-but-not-true → false")
op, neg = normalize({ op = "rx", negated = "true" })
ok(equal_pair(op, neg, "rx", false), "negated=\"true\" string → false (strict boolean)")
op, neg = normalize({ op = "rx", negated = 1 })
ok(equal_pair(op, neg, "rx", false), "negated=1 number → false")

-- ============================================================
-- legacy form (ModSec `!op`)
-- ============================================================
print("- legacy form, !rx")
op, neg = normalize({ op = "!rx" })
ok(equal_pair(op, neg, "rx", true), "{op=!rx} → (rx, true)")

print("- legacy form, !isSet")
op, neg = normalize({ op = "!isSet" })
ok(equal_pair(op, neg, "isSet", true), "{op=!isSet} → (isSet, true)")

print("- legacy form, !eq")
op, neg = normalize({ op = "!eq" })
ok(equal_pair(op, neg, "eq", true), "{op=!eq} → (eq, true)")

-- ============================================================
-- conflict resolution: legacy `!op` + explicit negated=false
-- The legacy `!` prefix always wins (the operator string is the
-- ground truth; the field is a hint that we override). This is the
-- pragmatic call — anyone writing `op = "!rx"` clearly meant
-- "negated", and the `negated=false` is probably an artifact of a
-- default-value copy-paste.
-- ============================================================
print("- conflict: !rx + negated=false → still negated (the `!` wins)")
op, neg = normalize({ op = "!rx", negated = false })
ok(equal_pair(op, neg, "rx", true), "legacy ! wins over an explicit negated=false")

print("- conflict: !rx + negated=true (consistent)")
op, neg = normalize({ op = "!rx", negated = true })
ok(equal_pair(op, neg, "rx", true), "redundantly negated → still (rx, true)")

-- ============================================================
-- edge cases
-- ============================================================
print("- missing op → empty string, not negated")
op, neg = normalize({})
ok(equal_pair(op, neg, "", false), "empty condition → (\"\", false)")

print("- op that doesn't start with ! is preserved")
op, neg = normalize({ op = "isSet" })
ok(equal_pair(op, neg, "isSet", false), "plain isSet")

print(string.format("\n%d test(s) failed", fails))
os.exit(fails == 0 and 0 or 1)
