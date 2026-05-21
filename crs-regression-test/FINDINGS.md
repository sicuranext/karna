# CRS regression-test findings

Running notes of issues hit while exercising the OWASP CRS regression
suite against Karna. Each entry is a real, reproducible observation —
not a theoretical concern. New finding = new entry at the top.

---

## #3 — pmFromFile doesn't match against `request.body` raw (open, biggest gap) (2026-05-21)

**Symptom.** When the PL1 regression suite is filtered to the supported
production posture (see `README.md` → "Why we bench at paranoia level
1"), the top failing single rule is **944130 — Suspicious Java class
detected** with **152 failures out of 418 test cases**. Same picture
on **932140 (152 failures)**, **944120 (104)**, **933100 (58)** — all
sharing the same shape: a `pmFromFile` operator with a wide set of
target variables including `REQUEST_BODY`, with payloads that put the
keyword inside an XML body, JSON body, or raw text body rather than
inside a form arg.

**Smoking-gun curl.**
```sh
# urlencoded → matches (rule fires, HTTP 403, body includes "id":"944130")
curl -X POST -d 'test=com.opensymphony.xwork2' \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     -H 'Host: integration.local' -H 'X-Karna-Test: true' \
     http://127.0.0.1:28000/post

# same keyword but in body raw → no match (HTTP 200 from request-termination)
curl -X POST --data-binary 'this has com.opensymphony.xwork2 inside as raw text' \
     -H 'Content-Type: text/plain' \
     -H 'Host: integration.local' -H 'X-Karna-Test: true' \
     http://127.0.0.1:28000/post

# same keyword in an XML attribute → no match
curl -X POST --data-binary '<?xml version="1.0"?><a x="com.opensymphony.xwork2"/>' \
     -H 'Content-Type: application/xml' \
     -H 'Host: integration.local' -H 'X-Karna-Test: true' \
     http://127.0.0.1:28000/post
```

**Three contributing causes identified, all need fixing:**

1. **`seclang.lua:146` maps `["XML"] = nil`** — the ModSecurity XPath
   variables `XML:/*` (all elements) and `XML://@*` (all attributes)
   are dropped at parse time. CRS rules that target XML-borne attacks
   (944130 test_id ≥ 6 explicitly use XML attributes) lose those
   target variables. **Fix:** map `XML` → `request.body.xml.value`
   and handle `XML://@*` → `request.body.xml.attr.value`. The
   underlying flattening already exists in `ka_body_parser.lua`
   (see L449–477).

2. **`pmFromFile` doesn't iterate on `request.body` as a single value.**
   `ka_engine.lua:2987` populates `request.body = <raw body>` in the
   inspection table for any non-empty body — so the variable IS
   present — but the rule-loop iteration evidently doesn't apply the
   phrase match against scalar inspection entries the way it does
   against per-key flattened structures (`request.arg.value:test`,
   `request.body.json.value:foo`, …). Net effect: `REQUEST_BODY` as a
   pmFromFile target is silently dead. **Fix:** ensure the
   condition-evaluation loop treats `request.body` as a legitimate
   pmFromFile target.

3. **`__match_op_pmFromFile` uses `string.match`, not literal substring.**
   `ka_engine.lua:1002` does `string_match(value:lower(), dvalue:lower())`
   which interprets `dvalue` as a Lua pattern, not a plain phrase.
   Entries in `java-classes.data` such as `com.opensymphony.xwork2`
   contain Lua metacharacters (`.`, `-`, `+`, `(`, `)` are all
   metachars). `.` matches any single character, so the match is
   wider than CRS intends — every legitimate match still works, but
   we may match strings that shouldn't (e.g. `com_opensymphony_xwork2`
   would also match). False-positive surface, plus pathological
   patterns could be slow. **Fix:** use `string.find(v, dvalue, 1, true)`
   (the `true` flag is "plain text search, no pattern interpretation").

**Combined impact:** fixing (2) alone unblocks the bulk of the 944130 /
932140 / 944120 / 933100 failures. Fixing (1) on top covers XML-shaped
payloads cleanly. Fixing (3) is cheap and removes a latent FP surface
that will only get noisier as more rules adopt pmFromFile against raw
body. Order of operations probably: (3) first (one-line safety win),
then (2) (the big detection unlock), then (1) (extends coverage to
XML attack variants).

**Why this took a while to spot.** The 944130 first test_id (urlencoded
arg) passes cleanly, so the rule reads as "implemented". Only inspecting
the per-test-id breakdown reveals that test_ids 1–5 (arg-shaped) pass
while 6+ (body-shaped) fail. Default suite reporting collapses these
into a single rule pass/fail count.

**Status.** Open. Documented for the next iteration — fix is a multi-step
engine change, not appropriate for an incidental commit.

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

## #4 — Phantom chained conditions accumulating across unrelated rules (open) (2026-05-21)

**Symptom.** Rule 942550 ("JSON-Based SQL Injection") reports
`#conditions=6` at evaluation time, even though the CRS .conf carries
exactly one SecRule for the rule id with no `chain` action. Rule 944120
("Java serialization") similarly shows `#conditions=2` despite being a
single 1+1 chain in CRS (one chained pair, not two). Net effect: a
positive first-condition match increments `matched_conditions` to 1,
fails the `matched_conditions == #rule.conditions` gate, and the rule
silently doesn't fire.

For 944120 the second condition is a real chain (MATCHED_VARS); after
the matched.value branch added in commit 0f1a54b the rule now fires
correctly when both halves match. But for 942550 — and likely for
several others in the residual "expect" failures of the PL1 suite —
there is no legitimate second condition: Karna's parser is appending
phantom continuations.

**Suspected source.** `seclang.parse` carries a `rule_is_chained` flag
between iterations of the rule loop. The flag is updated *after*
parsing each rule via `seclang.__is_chained(rule)`, which scans the
raw rule text for the literals `,chain`, `chain,`, or `chain"`. Any
SecRule that happens to contain one of those substrings in its
operator regex, its message, its tag list, or its actions section will
flip the flag on, and the next SecRule will be parsed as if it were a
chained continuation of the previous one — its variables become
conditions appended to the previous rule's id.

Confirmation would require tracing which raw rule before 942550 sets
the chain flag spuriously, and similarly back-tracking each of the
rules in the residual failure list to see if they share the same
shape (parsed with phantom extra conditions).

**Why this matters for PL1 coverage.** With #conditions inflated,
single-condition rules can never fire (matched_conditions=1 never
equals #conditions>=2). Several of the residual 304 "expect" failures
of the PL1 suite (942550=45, 943110=36, 920120=20, 920420=19,
922110=17, 920660=17, …) are plausibly variants of the same root
cause.

**Mitigation candidates** (not implemented in this round):
1. Tighten `__is_chained` to look only at the actions section, not
   the whole raw rule.
2. Anchor on word boundaries: match `\bchain\b` rather than the loose
   substring match.
3. Reset `rule_is_chained` at the *start* of each rule, only set it
   true when actually evaluating the actions string post-extraction.


## #5 — Residual PL1 long tail at 89.9% pass rate (2026-05-21)

After the cascade of engine fixes in this session (urldecode ARGS,
matched.value for chains, MULTIPART_PART_HEADERS mapping, PL2-skip
chain reset, ARGS_NAMES branch in the modern loop, gate-relaxation
config for the bench), Karna's PL1 CRS regression pass rate stands at
**89.9% (2478/2757)**. The residual ~280 failures are scattered
across many rules with low individual cardinality (top single is now
20). They share a few patterns:

- **TX variable chains** — rules like 920420 set
  `setvar:'tx.content_type=|%{tx.0}|'` then evaluate a chained
  condition `TX:content_type !@within %{tx.allowed_request_content_type}`.
  Karna's `setvar:tx.*` plumbing works, the `%{tx.*}` macro resolver
  works, but the resolution chain across multiple chained conditions
  with stateful TX writes isn't fully aligned with ModSec semantics
  for some specific patterns.

- **Cookie-borne attacks** — several 920* and 944* tests put the
  attack payload inside a Cookie header value. Karna parses cookies
  into `request.cookie.value:<name>` but a handful of edge cases
  (multi-value cookies, quoted cookies, oversized cookies) don't
  surface the right value to the rule.

- **`%{request_headers.host}` macro resolution** in operator values
  works for `endsWith` (943110 confirms), but doesn't yet for every
  operator variant.

- **Capture group propagation across chain conditions** mostly works
  (943110 confirms it). Edge cases where the captured group is then
  fed back into `%{tx.N}` macros in deeper conditions are spotty.

Investigation for each of these is single-rule-deep and the
detection unlock per round of work is low. Recommendation: ship the
current baseline, wire CI to assert ≥89.9% on every commit, and
chase the long tail rule-by-rule with focused commits over time
instead of trying to push the percentage higher in this same
session.

