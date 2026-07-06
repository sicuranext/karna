---
name: karna
description: Deploy, configure, and write rules for Karna, a source-available OWASP CoreRuleSet-compatible Web Application Firewall plugin for Kong Gateway. Use when installing or deploying Karna, editing its plugin configuration, authoring detection / sanitization / rate-limit rules, or taming CRS false positives.
---

# Operating Karna

Karna is a WAF engine that runs as a native Kong Gateway plugin (priority 8300).
It loads the OWASP CoreRuleSet at worker start and evaluates each request against
those rules plus any rules the operator writes. It is self-contained — it needs no
other plugin to work. This skill makes you effective at three jobs: **deploying**
Karna, **configuring** it, and **writing rules**.

## How to use this skill

Read the reference file for the job at hand — but for anything involving rules,
read **both** `reference/recipes.md` and `reference/rules.md`. Recipes gives the
worked pattern; rules gives the shared mechanics (phases, evaluation order,
variables, operators, actions) that every recipe relies on. A task that looks
like a single recipe often needs the mechanics too — e.g. combining several rules
in one phase depends on the evaluation order documented in `rules.md`. Don't load
files unrelated to the task.

| Job | Read |
|-----|------|
| Install / deploy (Docker or existing Kong), attach to a service | `reference/deploy.md` |
| Set or explain a plugin config option | `reference/configuration.md` |
| Write, compose, combine, or order rules (detection / sanitize / rate-limit / ban / FP) | `reference/recipes.md` **and** `reference/rules.md` |

**You do not need to read the Lua source to author rules.** Everything required
to write, combine, and order rules — variables, operators, transforms, actions,
phases, and evaluation order — is in `recipes.md` and `rules.md`. Treat those two
as authoritative for rule work. The engine source
(`kong/plugins/karna/modules/ka_engine.lua`) and schema
(`kong/plugins/karna/schema.lua`) are the ultimate source of truth and worth
reading only to confirm a deep engine internal the reference genuinely does not
cover — not for normal rule authoring.

## Golden rules (do not skip)

1. **Detection-only first, always.** Deploy and tune with
   `engine_blocking_mode: false`. Karna evaluates every rule and writes matches to
   the audit log but never blocks. Watch the log against real traffic, remove false
   positives (overrides / rule controls), then set `engine_blocking_mode: true`.

2. **Run the CRS regression after any rule or engine change.** Bring up the dev
   stack and run `crs-regression-test/start.py` before declaring a change done.
   A rule or engine edit that drops the pass count is a regression — investigate
   before shipping. See `reference/recipes.md`.

3. **`ignore_from_local_ips` defaults to `false`** (everything is inspected). If
   someone set it to `true`, requests from localhost / RFC1918 ranges — including a
   load balancer's private egress IP — are skipped, and a local-sourced attack will
   look like it "isn't being blocked". Check this first when blocking seems dead.

4. **Never benchmark or run load tests at `debug` log level.** Per-rule log spam
   tanks throughput. Keep `KONG_LOG_LEVEL=warn`.

5. **Validate config changes don't fight the always-on gates.** Allowed methods,
   path-character limits, denied headers, content-type/charset, and arg count run
   *before* the rule loop and fire regardless of blocking mode and CRS toggles. If
   a request is blocked "with everything off", these are usually why.

6. **Keep everything generic and public.** This repo is public and source-available
   under the Elastic License 2.0. Never add internal hostnames, customer names, or
   private infrastructure details to rules, config examples, or docs.

## The operating loop

1. Deploy in detection-only (`reference/deploy.md`).
2. Send representative traffic; read the audit log (default
   `/usr/local/openresty/nginx/logs`).
3. For each false positive, add a rule override or rule control
   (`reference/rules.md`, `reference/recipes.md`). Do not just disable the WAF.
4. Re-run the CRS regression to confirm you didn't break detection.
5. Flip `engine_blocking_mode: true` once the audit log is clean.

## Verifying your work

- Plugin loads: `curl -s http://localhost:8001/ | grep -o karna` (Admin API lists
  the plugin) and check the Kong error log for `WARN` lines from rule parsing.
- A rule fires: send a request that should match and confirm the audit-log entry
  (or the block) appears.
- Detection intact: the CRS regression pass count is at or above its prior level.
