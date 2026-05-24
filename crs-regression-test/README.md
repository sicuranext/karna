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

## Paranoia level

By default `fetch-tests.sh` filters tests to rules tagged
`paranoia-level/1`. CRS 4.26 ships **626 rules** spread across four
levels (PL1: 498 — PL2: 89 — PL3: 30 — PL4: 9), and the official
test suite carries cases for all four.

- `CRS_MAX_PL=1` (default) — PL1 only. The recommended bench for the
  default production posture (`config.paranoia_level=1`).
- `CRS_MAX_PL=2` — PL1+PL2. Use when measuring Karna against the
  higher-paranoia posture (`config.paranoia_level=2`). Karna treats
  PL2 as a first-class supported posture (current headline: ~96%
  PL2-tagged tests pass).
- `CRS_MAX_PL=0` — no filter, load every test (PL1+PL2+PL3+PL4).

**Important**: the Karna plugin's `paranoia_level` config controls
which rules ACTUALLY EVALUATE at runtime, independently of which
tests you've fetched. Set both: `CRS_MAX_PL=N` on `./fetch-tests.sh`
plus `PARANOIA=N` on `./configure-kong.sh`.

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

Two additional `pass*` paths are wired into `start.py`:

- **`KARNA_REMOVED_RULES`** — CRS rules Karna intentionally removes
  via `coreruleset_fix.global_fps` because the equivalent is enforced
  by a schema-level config knob (e.g., `911100` ↔
  `request_methods_allowed`, `920360` ↔ `limit_arg_name_length`).
  When the expected rule id is in this map, the test is flagged
  `passed* (covered by Karna config: <field>)`. See
  [`../kong/plugins/karna/rules/coreruleset_fix.lua`](../kong/plugins/karna/rules/coreruleset_fix.lua)
  for the full list and the per-rule rationale.
- **`KARNA_ARCH_RESIDUAL_TESTS`** — per-(rule, test) entries flagging
  individual cases that depend on Apache/ModSec-only semantics Karna
  won't replicate (invalid HTTP header names like `X.Filename` that
  nginx drops at the connection layer; URL-decoded `REQUEST_FILENAME`
  semantics). Flagged `passed* (arch: <reason>)`.

Both maps are visible at the top of `start.py` and every entry has
a one-line justification. If a fail isn't in either map and you
think it should be — please open an issue.

## Measuring the impact of `coreruleset_fix.lua`

`kong/plugins/karna/rules/coreruleset_fix.lua` is loaded unconditionally
at `init_worker`. See the file for the current entries and the
per-override rationale; every change is auditable and versioned with
the CRS release it targets.

To quantify the cost in CRS detection coverage, run the suite twice
— once with `coreruleset_fix.global_fps` active, once with the
overrides removed — and diff the per-test pass/fail. Make the
override layer a no-op by editing the file (return an empty
`global_fps = {}`), `docker compose restart kong`, re-run, restore.

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
