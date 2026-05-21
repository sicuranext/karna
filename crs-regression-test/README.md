# OWASP CoreRuleSet — regression test suite runner for Karna

Drives Karna against the official OWASP CRS regression test YAMLs and
reports how many tests pass / fail / are skipped. Use it to:

1. Measure Karna's CRS coverage on every release.
2. Quantify the operational impact of `coreruleset_fix.lua` by running
   the suite with and without the in-repo CRS fix layer.
3. Identify CRS operators / transformations Karna doesn't implement yet
   (failures clustered under the same opcode point at a gap).

## Layout

| File | Purpose |
|---|---|
| `start.py`                   | The runner. Loads a YAML test file (or directory), opens a raw socket to a running Kong, sends the constructed HTTP request, and inspects the response for the expected CRS rule id. |
| `fetch-tests.sh`             | Downloads the regression test YAMLs from the OWASP CRS GitHub release tarball into `./tests/`. Pin the version with `CRS_VERSION=...`; restrict paranoia level with `CRS_MAX_PL=...` (default `1`, see below). |
| `configure-kong.sh`          | Idempotent Kong setup (service, route, karna plugin instance, request-termination short-circuit). |
| `bench-coreruleset-fix.sh`   | Two-pass runner: with vs without `coreruleset_fix.lua`, then diff. |
| `toggle-crs-fix.sh`          | Swap `coreruleset_fix.lua` with an empty stub for the bench. |
| `run-categories.sh`          | Run the suite one category-directory at a time with a per-category wall-clock budget. Used for bisecting which test makes Kong stall. |
| `FINDINGS.md`                | Post-mortem of bugs surfaced by the suite (engine-level regex/parser fixes). |
| `tests/`                     | The downloaded (and filtered) YAMLs. **Not committed** (gitignored). |

## Why we bench at paranoia level 1 (PL1) only

By default `fetch-tests.sh` filters out YAML tests that target rules tagged
`paranoia-level/2` or higher. CRS 4.26 ships **626 rules** spread across
four levels (PL1: 498 — PL2: 89 — PL3: 30 — PL4: 9), and the official
test suite carries cases for all four. We benchmark only PL1 because:

- **PL1 is the only level deployable in production**. PL2+ are designed
  as escalating "we'll false-positive harder in exchange for catching
  more obscure attacks" tiers. Real WAF operators do not run anything
  above PL1 unless they're doing forensic work on a known target —
  PL2 alone is already enough to FP on legitimate traffic in most
  real-world applications (anything that POSTs structured JSON, uses
  modern Auth headers, accepts uploads, …).
- **A "fail" on a PL3 test is not a Karna gap**, it's a deliberate
  choice not to load that rule. Counting them as failures inflates the
  number and dilutes the signal: we want to know how Karna does on
  rules a real deployment would actually have on.
- **The supported operational surface of Karna is PL1**. Bug reports,
  performance promises, and CRS-compatibility claims are scoped there.
  PL2+ "best effort" support is fine, but it's not the measurement
  axis.

Override with `CRS_MAX_PL=2` (or higher) if you specifically want to
exercise PL2+ rules; set `CRS_MAX_PL=0` to disable the filter entirely.

## Prerequisites

- Python 3 with `pyyaml`: `pip install pyyaml`
- Docker + docker compose (for the Karna dev stack)
- A Kong service configured with the `karna` plugin enabled and routed
  at host `karna-test` (the runner hard-codes a few request shapes to
  this hostname for the dev-mode path in `ka_utils.dev_env_enabled`).

## End-to-end procedure

```sh
# 1. Bring up Karna + Postgres + Redis + echo upstream
docker compose up --build -d

# 2. Wait for Kong to be ready
until curl -s http://localhost:28001/ >/dev/null; do sleep 1; done

# 3. Create a service + route + plugin instance pointing at the echo upstream.
#    See docker/README.md for the canonical example; the relevant bits:
#      - host:        karna-test  (matches internal_dev_host in ka_utils.lua)
#      - plugin:      karna
#      - config:      private_debug=true, coreruleset_enabled=true,
#                     paranoia_level=1 (or higher to exercise PL2-4 rules)

# 4. Fetch the regression test YAMLs (matches CRS_VERSION in Dockerfile)
cd crs-regression-test
./fetch-tests.sh

# 5. Run the suite
python3 start.py --testfile tests/

# Useful flags:
#   --show-only-failed             keep the output focused on regressions
#   --testrule 932100              focus on a single rule
#   --testfile tests/REQUEST-942-APPLICATION-ATTACK-SQLI/  one category
#   --host / --port                non-default Kong address
#   --debug                        print outgoing curl + raw response
```

The runner attaches two request headers to every test it sends:

- `x-karna-test: true` — flips Karna into dev mode together with the
  `karna-test` Host header (see `ka_utils.dev_env_enabled`).
- `x-karna-test-rule-id: <id>` — when `private_debug` is enabled on the
  plugin instance, restricts rule evaluation to this id only. Lets you
  bisect failures without rule cross-talk.

## How a test is judged

Per stage, the runner looks at the upstream response body for substring
matches:

- `output.log.expect_ids` — at least one of the listed CRS rule ids
  must appear as `"id":"<rule_id>"` in the response. Pass means the
  rule fired.
- `output.log.no_expect_ids` — the listed ids must NOT appear. Pass
  means the rule correctly stayed silent (no false positive).
- `output.log_contains` / `no_log_contains` — substring presence /
  absence check on the response body, used as a fallback when the
  YAML doesn't enumerate ids.

403 responses with `"Request URI path contains illegal characters"`
and 405 responses are counted as **pass*** with an asterisk — they
indicate Karna's always-on validation gates blocked the request before
the rule engine even ran, which is the expected behaviour for several
CRS tests.

## Measuring the impact of `coreruleset_fix.lua`

`kong/plugins/karna/rules/coreruleset_fix.lua` is loaded unconditionally
at `init_worker`. It touches 46 distinct CRS rule ids (6 outright
removals, 19 transformation-function swaps, 24 condition replacements,
and a handful of others — see [the file](../kong/plugins/karna/rules/coreruleset_fix.lua)).
Its rationale is operational (false-positive control from production
deployments), not "the CRS rule is wrong".

To measure how much it costs in CRS detection coverage:

```sh
# baseline (with the fix layer applied — current default)
python3 start.py --testfile tests/ > with_fix.log

# stub the fix layer out — quickest way is to comment its load in
# handler.lua, restart Kong (`docker compose restart kong`), and re-run
python3 start.py --testfile tests/ > without_fix.log

diff <(grep -E "passed|failed" with_fix.log) <(grep -E "passed|failed" without_fix.log)
```

Tests that pass *without* the fix but fail *with* the fix are the cost
of the operational layer — those are the rule ids where
`coreruleset_fix` has narrowed detection in exchange for fewer FPs in
production traffic. Discuss each one before keeping or unwinding it.

## Caveats

- The runner waits up to 5 seconds per request. Very slow Kong startups
  (CRS rule parsing on the first request after `kong reload`) can mark
  the early tests as timeouts. Run the suite once to warm the worker,
  then re-run.
- `private_debug` is verbose. For full-suite runs in CI, turn it off on
  the plugin instance — but then `x-karna-test-rule-id` filtering won't
  apply and every rule fires for every test.
- `start.py` is intentionally a no-deps script (just `pyyaml`). Don't
  grow it into a framework — it's meant to be readable end-to-end.
