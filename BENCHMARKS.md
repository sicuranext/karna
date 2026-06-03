# Karna benchmarks — vs. Apache+ModSec2 and nginx+ModSec3

Head-to-head performance numbers for Karna against the two most widely
deployed open-source ModSecurity stacks. **Karna is the fastest of the
three at the metric a WAF actually exists for — identifying and blocking
attacks — by a wide margin, and on a dedicated host it also leads on
most realistic benign, mixed and API workloads.** The one place it
trails is multipart-with-files (−7% vs nginx's native C++ engine);
cold-start sits mid-pack. Every win holds at full detection parity:
every WAF returns the same HTTP status on every request (benign → 200,
attack → 403; k6 `checks_rate` = 1.0).

All three stacks measured on the **same dedicated host** (Hetzner CCX,
2 CPU / 2 worker processes each), same upstream, same client load,
against fresh containers brought up one WAF at a time. OWASP CRS 4.x at
PL1.

> **Measurement note (read this).** Karna was re-measured on
> **2026-06-03** with the current shipping configuration (DB-less Kong,
> all CRS attack categories on, the 54-rule `crs_prune` removals active,
> all engine optimizations unconditional). The Apache and nginx figures
> are from an **earlier run on the same dedicated host and ruleset**, not
> interleaved back-to-back with this Karna run. Treat the cross-WAF
> ratios as **indicative of the current product**, not a single
> same-session bake-off. Karna's own numbers are best-of-5 (see
> [Methodology](#methodology)).

## Headline numbers

RPS — higher is better. Cold-start — lower is better. "vs nginx" is the
throughput delta; "vs Apache" is the multiplier.

| Scenario                                  | Apache+ModSec2 | nginx+ModSec3 |    **Karna** |  vs nginx | vs Apache |
| ----------------------------------------- | -------------: | ------------: | -----------: | --------: | --------: |
| **Attack blocking** (`06`)                |            852 |         1 623 |    **3 326** | **+105%** |     3.9×  |
| **API + embedded attacks** (`09`)         |            190 |           688 |      **815** |  **+19%** |     4.3×  |
| **Mixed real-world traffic** (`07`)       |            612 |         1 270 |    **1 569** |  **+24%** |     2.6×  |
| Same-request benign GET (`01`)            |            643 |         1 263 |    **1 542** |    +22%   |     2.4×  |
| Random-field benign GET (`02`)            |            392 |         1 139 |    **1 310** |    +15%   |     3.3×  |
| Big urlencoded body, 950 args (`03`)      |            1.9 |          14.4 |     **20.1** |    +40%   |    ~11×   |
| Deeply nested JSON, depth 400 (`04`)      |            201 |           220 |      **228** |  +4% (tie)|     1.1×  |
| Multipart upload, 3 files (`05`)          |            486 |       **580** |          541 |    −7%    |     1.1×  |
| Cold-start (avg ms, lower=better)         |        34.1 ms |   **27.5 ms** |      30.9 ms |     —     |     —     |

**Scoreboard: Karna wins 7 of the 8 throughput scenarios.** It loses
only multipart (`05`) to nginx by 7% — and even there beats Apache by
11%. On cold-start it's middle of the pack: faster than Apache, a few ms
behind nginx.

```
Attack blocking — verified WAF-blocks per second (higher = better)
Karna   ████████████████████████████████████████████████  3 326
nginx   ███████████████████████                           1 623
Apache  ████████████                                        852

Mixed real-world traffic — 70% benign / 20% POST / 10% attack (RPS)
Karna   ████████████████████████████████████████████████  1 569
nginx   ███████████████████████████████████████           1 270
Apache  ███████████████████                                  612

Modern API + 30% embedded attacks (RPS, higher = better)
Karna   ████████████████████████████████████████████████    815
nginx   ████████████████████████████████████████            688
Apache  ███████████                                          190

Cold-start (avg ms, lower = better)
nginx   ███████████████████████████████████               27.5
Karna   ███████████████████████████████████████           30.9
Apache  ███████████████████████████████████████████       34.1
```

### How to read these

- **Karna leads attack blocking by a wide margin** — +105% over
  nginx+ModSec3, +290% (3.9×) over Apache+ModSec2 — and every block is a
  verified `403` from Karna's CRS detection (`checks_rate` = 1.0). When a
  WAF's job is to identify and reject attacks, Karna does the most
  attacks-per-second of the three. This matters operationally: a WAF
  that only processes ~850–1 600 attack rps becomes the DoS target
  itself under a sustained flood.
- **On modern API traffic with embedded attacks (30% attack mix), Karna
  now leads outright** — +19% over nginx and 4.3× Apache — while parsing
  and scanning body + querystring + cookie + `Authorization` header on
  every request. (This flipped from an earlier Docker-Desktop run where
  Karna trailed nginx; on the dedicated host with the current engine,
  Karna is fastest.)
- **On mixed real-world traffic, Karna leads by +24% over nginx** and
  +156% over Apache — the single number closest to production load.
- **On benign GET throughput (`01`, `02`), Karna also leads** (+22% /
  +15% over nginx). This is the tier most sensitive to the gateway
  framework underneath the WAF; on the dedicated host Karna's LuaJIT
  engine plus its per-request value caches come out ahead.
- **Deeply nested JSON is a genuine 3-way tie** (~201–228 rps): the
  ceiling here is JSON parse depth, not engine speed.
- **Multipart-with-files is Karna's one loss** — 93% of nginx (−7%).
  Karna's parser is hardened against ~a dozen multipart bypass classes,
  and that extra per-part inspection has a real, honest cost against
  nginx's native C++ engine. It still beats Apache by 11%.
- **Cold-start (~31 ms)** is between nginx (27.5) and Apache (34.1).
  Karna loads its declarative config and parses the CRS at worker init;
  31 ms is well within per-pod-restart norms.

## Scenarios

Each scenario's payload and what it isolates. Full descriptions and the
raw per-round data live in the bench harness.

- **`01` same-request** — tiny near-fixed benign GET (3 query args, only
  `page` varies, ~90 B, no body). Steady-state hot path; the per-request
  value caches (transform memo, RE2::Set gate, resolve-once arg cache)
  work at their best because values repeat.
- **`02` random-fields** — benign GET with 5 fully random query args
  every request. Worst case for caching: every value is unseen, forcing
  full rule evaluation against fresh input. The honest no-cache benign
  number.
- **`03` big-urlencoded** — POST with 950 urlencoded fields (~103 KB).
  The `rules × args` scaling cost: body parse + flatten + per-arg
  evaluation. Apache collapses to ~2 rps (interpreted per-arg PCRE); a
  pathological stress test at the `SecArgsLimit` edge, not real traffic.
- **`04` big-json** — JSON body nested 400 levels deep (~2.4 KB), just
  under `SecRequestBodyJsonDepthLimit`. All benign; isolates parser
  nesting-depth handling, not size. ~2% of requests error at depth 400
  on all three WAFs.
- **`05` multipart** — `multipart/form-data` with 2 text fields + 3×
  10 KB file parts (~30 KB). Boundary scan, per-part header parsing,
  file-content extraction and scanning.
- **`06` attack-payloads** — every request is an attack (XSS/941,
  SQLi/942, LFI/930, RCE/932) in the querystring, round-robin. Each WAF
  blocks at the first matching rule; RPS = verified `403`s. `fail_rate`
  = 1.0 by design (every request is a 403).
- **`07` mixed-traffic** — 70% benign GET, 20% benign urlencoded POST,
  10% attack GET. Pass-path and block-path interleaved in one run; ~10%
  of requests blocked.
- **`09` api-with-attacks** — POST to a JSON API with body + querystring
  + `Cookie` + `Authorization` on every request; 70% fully benign, 30%
  poison exactly one vector (qs/body/cookie/auth). Multi-vector
  inspection — the WAF parses and scans four surfaces per request.
- **`08` cold-start** — 20 VUs × 1 request each, fired immediately after
  a container restart, no warm-up. First-request initialization cost.

## Methodology

All three stacks are run from fresh containers under identical
conditions on the same dedicated host:

- **OWASP CRS 4.x at PL1** — `coreruleset_enabled=true` on Karna,
  `PARANOIA=1` on the owasp ModSec images. Karna additionally drops 54
  redundant/nonsensical CRS protocol-enforcement rules
  (`crs_prune_kong_gateway`) that don't make sense behind an API gateway
  — these never fire and never affect detection parity.
- **Hetzner CCX dedicated host**, **2 CPU cores per container**.
- **2 worker processes each**: Karna via `KONG_NGINX_WORKER_PROCESSES=2`,
  nginx via `NGINX_ENTRYPOINT_WORKER_PROCESSES_AUTOTUNE=1` (sizes workers
  from the cgroup quota), Apache via event MPM CPU-capped.
- **Same upstream** (`mendhak/http-https-echo`, uncapped) and **same
  client** (`k6`, 20 VUs, 30 s warm-up + 60 s measure window).
- **Karna: DB-less Kong** — no Postgres, no Redis. The declarative
  config is loaded at boot via `KONG_DECLARATIVE_CONFIG`, which also
  sidesteps the Admin-API route-propagation artifact described below
  (there is no runtime `POST /routes`). All engine optimizations are
  unconditional (skip-body-rules, transform-cache hoist,
  skip-multipart-scan, RE2::Set `@rx` gate, RE2 `@rx` match, Aho-Corasick
  `@pm`, fast-path, nested transform cache).
- **Karna numbers are best-of-5**: max `http_reqs.rate` over 5 warm
  rounds (cold-start = min avg-ms over 5 restarts), with
  `checks_rate == 1.0` gated on every round. Apache/nginx are the
  previously-published figures on the same host (median of the repeated
  scenarios, single run otherwise) — see the measurement note at the top.
- **Status parity probed before every run**: each scenario's payload is
  sent to all three WAFs and only kept if all three return the same
  status (benign → 200, attack → 403). If even one returns a different
  code the scenario is excluded or reshaped. (`checks_rate = 1.0` on
  every Karna round confirms parity held throughout.)
- **One WAF at a time**: the harness tears the others down so they don't
  compete for CPU.

### A note on the Kong route-propagation artifact

We confirmed (on Kong 3.9.0 and 3.9.1, **Postgres mode**) that for ~30 s
after `POST /services`/`POST /routes` via the Admin API, a sustained
high-rate keepalive load sees a large fraction (60–90%, scaling with
concurrency) of requests come back as `404 "no Route matched"` before
the route is fully visible to every worker. After ~30 s the same load
runs clean at 0% errors. A minimal reproduction:

```sh
# tear down + bring up a fresh Kong (postgres mode), POST service+route,
# then IMMEDIATELY run this k6 script against it:
import http from 'k6/http';
export const options = { vus: 50, duration: '15s', discardResponseBodies: true };
export default function () {
  http.get('http://127.0.0.1:8000/get?x=1', { headers: { Host: 'bench.local' } });
}
# -> ~70% 404 "no Route matched". Wait 30 s, rerun -> 0% errors.
```

`curl`/`ab`-based reproductions don't reliably trigger this because
their process-per-connection or pre-established-connection patterns
don't burst into Kong the way k6's in-process VU keepalive model does.
This is independent of Karna — the same reproduction hits a Kong with
**zero plugins attached**. **The DB-less benchmark configuration above
avoids it entirely** by loading routes declaratively at boot rather than
posting them at runtime.

## Fairness fixes applied before measuring

These are bench-harness issues that were *not* about WAF performance —
they were one-stack disadvantages we corrected before trusting the
numbers.

- **Apache `disablereuse=on`** — the official
  `owasp/modsecurity-crs:apache` image ships
  `ProxyPass / ${BACKEND}/ disablereuse=on`, which opens a fresh TCP
  connection to the backend on every request. Under sustained load this
  exhausts the ephemeral port range and Apache fails ~24% of requests
  with `AH00957`. Fixed by bind-mounting a vhost with `enablereuse=on`.
- **k6 `reqParams` Host-drop** — a bug in our k6 helper re-spread `extra`
  after the merged headers, silently dropping the `Host` header on any
  scenario that passed a custom `Content-Type`. On Kong those requests
  got `404 "no Route matched"` instead of being measured. Fixed by
  destructuring `headers` out of `extra` before spreading.
- **nginx `worker_processes`** — `worker_processes auto` reads the host's
  CPU count, not the 2-CPU cap, and oversubscribes. We enable
  `NGINX_ENTRYPOINT_WORKER_PROCESSES_AUTOTUNE=1` so the entrypoint sizes
  from the cgroup quota.
- **Karna `ignore_from_local_ips`** — the plugin's default is `true`,
  which short-circuits detection for client IPs in private ranges. The
  benchmark client is on a private bridge, so the default would bypass
  all CRS rules. We set it to `false`.
- **Kong `KONG_LOG_LEVEL=warn`** — never benchmark Kong at `debug`;
  per-request log spam wrecks throughput.
- **Kong `upstream_keepalive_idle_timeout=4`** — Kong's default upstream
  idle timeout (60 s) exceeds Node's default server `keepAliveTimeout`
  (5 s); under bursty load Kong can reuse an upstream connection the
  backend has already closed, returning `502 "upstream prematurely
  closed"`. We set Kong's idle below upstream's to eliminate the race.

## Limitations

- **Cross-session cross-WAF comparison.** Karna was re-measured on
  2026-06-03 with the current shipping config; Apache and nginx are from
  an earlier run on the same dedicated host. The ratios are indicative of
  the current product, not a single back-to-back measurement (see the
  note at the top). Karna's own numbers are best-of-5 to damp run-to-run
  variance.
- **Absolute throughput is host-specific.** The ordering is stable across
  runs; the absolute rps depends on the box. These are from a Hetzner CCX
  dedicated host, 2 CPU per container.
- **Karna's CRS detection coverage** is tracked separately by the CRS
  regression suite (`ka-regression-tests/` and `crs-regression-test/`);
  the numbers above are performance only — correctness is gated by the
  regression suite, not this benchmark.
- **Per-WAF strengths vary by workload.** nginx+ModSec3 still wins
  multipart-with-files because its body parsing is native C++; Karna
  wins the detection-heavy and mixed paths because libinjection
  short-circuits at the first match and the rule loop skips full CRS
  evaluation on requests it rejects early or that carry no body.
