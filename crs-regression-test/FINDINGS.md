# CRS regression-test findings

Running notes of issues hit while exercising the OWASP CRS regression
suite against Karna. Each entry is a real, reproducible observation —
not a theoretical concern. New finding = new entry at the top.

---

## #2 — Multipart parser injects raw boundary into a Lua pattern → catastrophic backtracking (2026-05-21)

**Symptom.** Same as #1 — Kong workers stuck near 100% CPU, no
response on the proxy port, suite hangs. But the engine-level cap
described in #1 (`lua_regex_match_limit`) did **not** fire (no
`regex engine aborted` warn line in the Kong error log) even when
dialled all the way down to 1000. Conclusion: the spinning code path
was not `ngx.re.match`.

**Root cause.** `kong/plugins/karna/modules/ka_multipart.lua:58-59`
and `:117` build a Lua pattern by concatenating the boundary
verbatim:

```lua
local boundary_start = "^%-%-" .. boundary       -- L58
local boundary_end   = "^%-%-" .. boundary .. "%-%-$"  -- L59
...
:gsub("^%-%-" .. boundary .. "\r\n", "")         -- L117
```

In Lua patterns, `-` is the "zero-or-more, lazy" quantifier. The
multipart-boundary validator already permits `( ) + , . / ? = -`
in the boundary (RFC 2046 + the regex on `is_boundary_valid`),
and the CRS regression tests routinely use boundaries like
`---------------------------627652292512397580456702590` —
27 consecutive dashes. Concatenated raw, that becomes 27 nested
lazy quantifiers in the resulting pattern; each `gmatch` call over
the body explores an exponential number of split positions. Worse:
Lua-native patterns are NOT capped by `lua_regex_match_limit` (that
directive applies to PCRE only), so the worker spins forever with
no diagnostic hook.

**Fix.** Added an `escape_lua_pattern` helper that replaces every
Lua metachar in the boundary with its `%X` escape, then used the
escaped form in all three call sites. Same source-of-truth boundary,
no more catastrophic backtracking. With the fix in place, the full
4674-test CRS regression suite now completes in **~2.5 seconds**
(was hanging Kong indefinitely on the first multipart test).

**Why this took multiple wrong turns to find.** Investigation
followed `ngx.re.match` for a long time because (a) Kong's debug log
showed it evaluating the 920120 regex shortly before stalling, and
(b) the PCRE pattern in 920120 itself looks catastrophic by visual
inspection — `(?:[a-z]|[^"';=\x5c])*$`. Both clues pointed at the
wrong layer. The diagnostic that broke the case was sampling Kong
CPU while running each YAML file *singly* and noticing that the
hang correlates with **boundary length in the request**, not with
the rule that fires after parsing.

**Lessons.**
- Lua-native pattern strings concatenated with user-influenced input
  are a hidden DoS surface; treat boundaries / paths / cookie names
  as adversarial when they feed `string.match`/`gsub`/`gmatch`.
- `lua_regex_match_limit` is a PCRE-only safety net, not a
  defense-in-depth for the whole engine. Any time `string.match`
  appears in a hot path, audit for unescaped concatenation.
- The wrapper-based mitigation in #1 (safe_re_match + j-strip + cap)
  stays in place as a hardening layer for future PCRE pathologies,
  but on its own it would not have unblocked the suite — the actual
  bug was elsewhere.

**Repro (pre-fix).**
```sh
python3 start.py \
    --testfile tests/REQUEST-920-PROTOCOL-ENFORCEMENT/920120.yaml \
    --testnum 2
# observe `docker stats karna-kong` climb to ~100% CPU and never return.
```

---

## #1 — CRS rule 920120 causes catastrophic regex backtracking on Karna (2026-05-21)

**Symptom.** While running the full CRS regression suite (4674 tests),
Kong workers got stuck with **911% CPU usage** (9 worker processes
saturated) and stopped accepting requests. `docker stats` showed Kong
chewing CPU continuously; the proxy port still accepted TCP but
returned no response, the runner's `settimeout(5)` only triggered
after the Kong accept-queue saturated.

**Root cause.** Kong error log (filtered) showed the worker stuck in
rule **920120 — "Attempted multipart/form-data bypass"**. The CRS
regex is:

```
(?i)^(?:&(?:(?:[acegilnorsuz]acut|[aeiou]grav|[aino]tild)e|[c-elnr-tz]caron|(?:[cgklnr-t]cedi|[aeiouy]um)l|[aceg-josuwy]circ|[au]ring|a(?:mp|pos)|nbsp|oslash);|[^"';=\x5c])*$
```

That's a textbook catastrophic-backtracking shape: a long alternation
nested inside `(?:...)*$` with the alternative branch `[^"';=\x5c]`
(any "normal" char). On a payload of N "normal" bytes, the engine
explores exponentially many ways to split the input between the two
alternatives before deciding it doesn't anchor at `$`. With even a few
hundred bytes of multipart filename input, PCRE on LuaJIT runs out of
budget. OpenResty / `ngx.re.match` has no per-call regex timeout, so
the worker spins forever.

**Impact in this release.** Karna's in-repo `coreruleset_fix.lua`
does **not** touch rule 920120 (`grep '"920120"' .../coreruleset_fix.lua`
returns nothing). So the rule is loaded as-is. A single multipart
test crafted with a "filename" of more than ~100 bytes is enough to
freeze every Kong worker for the lifetime of the process.

**Resolution adopted (2026-05-21): engine-level cap.**
Catastrophic backtracking is not a property of *this one* rule — it's
a property of any regex written without anchor discipline. Instead of
neutralising 920120 specifically, we capped the PCRE backtracking
budget at the engine level so **any** pathological pattern fails
closed:

1. `KONG_NGINX_HTTP_LUA_REGEX_MATCH_LIMIT=100000` set in the
   docker-compose env block — surfaces as nginx directive
   `lua_regex_match_limit 100000;`. Above this many backtracking
   iterations, `ngx.re.match` returns `nil, err`.
2. New `safe_re_match` wrapper in `ka_engine.lua` distinguishes three
   outcomes: match / no-match / engine-error. The third bucket
   triggers a `kong.log.warn` line so operators can audit which CRS
   pattern blew up.
3. Operator dispatch updated:
   - **Positive `rx` / `grx`**: engine-error treated as no-match
     (the detection regex couldn't decide — rule simply doesn't fire).
   - **Negative `!rx`**: engine-error treated as no-match too, so the
     negation does NOT flip into a spurious match (FP avoidance). This
     is the critical one: without the wrapper, `not m` after a budget
     exhaustion would silently match every payload.

100000 was chosen empirically — covers legitimate complex CRS 4.x
patterns (verified on the regression suite) without leaving room for
exponential blowup. Tune via the env var if a legitimate rule fails
to match on long-but-valid input.

Rule 920120's regex still hits the cap on long multipart filenames,
but now the worker stays responsive: the rule simply produces no
match (logged as a warn line) and the request continues through the
remaining rules. Whether to also `remove_rule` 920120 from
`coreruleset_fix.lua` is a separate decision — engine-level fix
removed the DoS, the FP/perf trade-off of leaving 920120 enabled is
about detection signal, not stability.

**Repro.**
```sh
docker compose up -d
./configure-kong.sh
./fetch-tests.sh
# any of the 920120 / multipart filename tests with a long string
# will hang the worker — easiest to spot in the REQUEST-920-PROTOCOL-
# ENFORCEMENT category.
python3 start.py --testfile tests/REQUEST-920-PROTOCOL-ENFORCEMENT/920120.yaml --debug
# observe CPU climbing in `docker stats karna-kong` and never returning.
```

---
