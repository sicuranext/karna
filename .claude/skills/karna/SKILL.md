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

Read the reference file for the job at hand. Do not load all of them up front.

| Job | Read |
|-----|------|
| Install / deploy (Docker or existing Kong), attach to a service | `reference/deploy.md` |
| Set or explain a plugin config option | `reference/configuration.md` |
| Write a rule: variables, operators, transforms, actions, controls | `reference/rules.md` |
| Do a concrete task (block X, sanitize Y, rate-limit Z, fix an FP) | `reference/recipes.md` |

The authoritative source for config is `kong/plugins/karna/schema.lua`; for the
rule engine it is `kong/plugins/karna/modules/ka_engine.lua`. When in doubt, read
the code, not your memory.

## Golden rules (do not skip)

1. **Detection-only first, always.** Deploy and tune with
   `engine_blocking_mode: false`. Karna evaluates every rule and writes matches to
   the audit log but never blocks. Watch the log against real traffic, remove false
   positives (overrides / rule controls), then set `engine_blocking_mode: true`.

2. **Run the CRS regression after any rule or engine change.** Bring up the dev
   stack and run `crs-regression-test/start.py` before declaring a change done.
   A rule or engine edit that drops the pass count is a regression — investigate
   before shipping. See `reference/recipes.md`.

3. **`ignore_from_local_ips` defaults to `true`.** Requests from localhost /
   private ranges are skipped. When testing from the same host, set it to `false`
   or it will look like "the CRS is not loading".

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
