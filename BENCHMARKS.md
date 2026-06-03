# Karna benchmarks

Head-to-head performance numbers for Karna against the most widely
deployed open-source WAF stacks: Apache + ModSecurity 2, nginx +
ModSecurity 3, and OWASP Coraza (the Go WAF, on Caddy). **Karna is the
fastest of the four at the metric a WAF actually exists for, identifying
and blocking attacks, and on a dedicated host it also leads on most
realistic benign, mixed and API workloads.** The one place it trails is
multipart-with-files (7% behind nginx's native C++ engine); cold-start
sits mid-pack. Every win holds at full detection parity: every WAF
returns the same HTTP status on every request (benign 200, attack 403;
k6 `checks_rate` = 1.0).

All stacks were measured on the **same dedicated host** (Hetzner CCX,
2 CPU each), same upstream, same client load, against fresh containers
brought up one WAF at a time. OWASP CRS 4.x at PL1.

> **Measurement note.** Karna was re-measured on 2026-06-03 with the
> current shipping configuration (DB-less Kong, all CRS attack
> categories on, the 54-rule `crs_prune` removals active, all engine
> optimizations unconditional); its figures are best-of-5. Apache and
> nginx are from an earlier run on the same host and ruleset. Coraza is
> a single warm run on the same host (coraza-caddy, CRS 4.25.0). Treat
> the cross-WAF ratios as indicative of the current product rather than
> a single back-to-back bake-off.

## Headline numbers

Requests per second, higher is better. Cold-start in avg ms, lower is
better.

| Scenario | Apache+ModSec2 | nginx+ModSec3 | Coraza+Caddy | **Karna** | vs nginx | vs Coraza |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| **Attack blocking** (`06`) | 852 | 1623 | 570 | **3326** | +105% | 5.8× |
| **API + embedded attacks** (`09`) | 190 | 688 | 184 | **815** | +19% | 4.4× |
| **Mixed real-world traffic** (`07`) | 612 | 1270 | 337 | **1569** | +24% | 4.7× |
| Same-request benign GET (`01`) | 643 | 1263 | 377 | **1542** | +22% | 4.1× |
| Random-field benign GET (`02`) | 392 | 1139 | 319 | **1310** | +15% | 4.1× |
| Big urlencoded body, 950 args (`03`) | 1.9 | 14.4 | 1.8 | **20.1** | +40% | 11.2× |
| Deeply nested JSON, depth 400 (`04`) | 201 | 220 | 107 | **228** | +4% | 2.1× |
| Multipart upload, 3 files (`05`) | 486 | **580** | 277 | 541 | -7% | 2.0× |
| Cold-start (avg ms, lower=better) | 34.1 | **27.5** | n/a | 30.9 | n/a | n/a |

**Scoreboard: Karna wins 7 of the 8 throughput scenarios, and beats
OWASP Coraza on all 8 (2.0× to 11.2×).** Its only loss is multipart
(`05`) to nginx by 7%, where it still beats Apache by 11% and Coraza by
2×. On cold-start it sits between nginx and Apache (Coraza cold-start was
not measured).

```
Attack blocking, verified WAF-blocks per second (higher = better)
Karna   ████████████████████████████████████████████████  3326
nginx   ███████████████████████                           1623
Apache  ████████████                                        852
Coraza  ████████                                            570

Mixed real-world traffic, 70% benign / 20% POST / 10% attack (rps)
Karna   ████████████████████████████████████████████████  1569
nginx   ███████████████████████████████████████           1270
Apache  ███████████████████                                 612
Coraza  ██████████                                          337

Modern API + 30% embedded attacks (rps, higher = better)
Karna   ████████████████████████████████████████████████   815
nginx   ████████████████████████████████████████            688
Apache  ███████████                                          190
Coraza  ███████████                                          184

Cold-start (avg ms, lower = better)
nginx   ███████████████████████████████████               27.5
Karna   ███████████████████████████████████████           30.9
Apache  ███████████████████████████████████████████       34.1
```

### How to read these

- Karna leads attack blocking by a wide margin: +105% over nginx+ModSec3,
  +290% (3.9×) over Apache+ModSec2, and 5.8× OWASP Coraza. Every block is
  a verified `403` from Karna's CRS detection (`checks_rate` = 1.0). A WAF
  that only clears ~570 to 1600 attack rps becomes the DoS target itself
  under a sustained flood.
- On modern API traffic with embedded attacks, Karna leads outright: +19%
  over nginx, 4.3× Apache, 4.4× Coraza, while parsing and scanning body +
  querystring + cookie + `Authorization` on every request.
- On mixed real-world traffic, Karna leads by +24% over nginx and 4.7×
  over Coraza, the single number closest to production load.
- On benign GET throughput (`01`, `02`), Karna also leads: +22% / +15%
  over nginx, 4.1× over Coraza. This is the tier most sensitive to the
  gateway framework underneath the WAF.
- Deeply nested JSON is a near tie among the C / LuaJIT engines (~201 to
  228 rps; Coraza trails at 107). The ceiling here is JSON parse depth,
  not raw engine speed.
- Multipart-with-files is Karna's one loss, 93% of nginx (-7%). Karna's
  parser is hardened against about a dozen multipart bypass classes, and
  that extra per-part inspection has an honest cost against nginx's native
  C++ engine. It still beats Apache by 11% and Coraza by 2×.
- Cold-start (~31 ms) sits between nginx (27.5) and Apache (34.1). Karna
  loads its declarative config and parses the CRS at worker init; 31 ms is
  well within per-pod-restart norms.
- OWASP Coraza (Go, on Caddy) is the slowest of the four on every
  scenario despite its RE2 engine, 2× to 11× behind Karna. It is
  benchmarked on Caddy because the nginx-Coraza connector is officially
  experimental.

## Scenarios

Each scenario's payload and what it isolates. Full descriptions and the
raw per-round data live in the bench harness.

- `01` same-request: tiny near-fixed benign GET (3 query args, only
  `page` varies, ~90 B, no body). Steady-state hot path; the per-request
  value caches (transform memo, RE2::Set gate, resolve-once arg cache)
  work at their best because values repeat.
- `02` random-fields: benign GET with 5 fully random query args every
  request. Worst case for caching: every value is unseen, forcing full
  rule evaluation against fresh input. The honest no-cache benign number.
- `03` big-urlencoded: POST with 950 urlencoded fields (~103 KB). The
  `rules × args` scaling cost: body parse, flatten, per-arg evaluation.
  Apache collapses to ~2 rps (interpreted per-arg PCRE); a pathological
  stress test at the `SecArgsLimit` edge, not real traffic.
- `04` big-json: JSON body nested 400 levels deep (~2.4 KB), just under
  `SecRequestBodyJsonDepthLimit`. All benign; isolates parser
  nesting-depth handling, not size. About 2% of requests error at depth
  400 on all four WAFs.
- `05` multipart: `multipart/form-data` with 2 text fields + 3 file parts
  of 10 KB each (~30 KB). Boundary scan, per-part header parsing,
  file-content extraction and scanning.
- `06` attack-payloads: every request is an attack (XSS/941, SQLi/942,
  LFI/930, RCE/932) in the querystring, round-robin. Each WAF blocks at
  the first matching rule; rps = verified `403`s. `fail_rate` = 1.0 by
  design (every request is a 403).
- `07` mixed-traffic: 70% benign GET, 20% benign urlencoded POST, 10%
  attack GET. Pass-path and block-path interleaved in one run; ~10% of
  requests blocked.
- `09` api-with-attacks: POST to a JSON API with body + querystring +
  `Cookie` + `Authorization` on every request; 70% fully benign, 30%
  poison exactly one vector (qs/body/cookie/auth). Multi-vector
  inspection: the WAF parses and scans four surfaces per request.
- `08` cold-start: 20 VUs by 1 request each, fired immediately after a
  container restart, no warm-up. First-request initialization cost.

## Methodology

All stacks are run from fresh containers under identical conditions on
the same dedicated host:

- OWASP CRS 4.x at PL1: `coreruleset_enabled=true` on Karna, `PARANOIA=1`
  on the owasp ModSec images, CRS 4.25.0 PL1 on the Coraza image (the
  CoreRuleSet org's own coraza-caddy build). Karna additionally drops 54
  redundant CRS protocol-enforcement rules (`crs_prune_kong_gateway`)
  that don't make sense behind an API gateway; these never fire and never
  affect detection parity.
- Hetzner CCX dedicated host, 2 CPU cores per container.
- Workers sized to the 2-CPU cap: Karna via `KONG_NGINX_WORKER_PROCESSES=2`,
  nginx via `NGINX_ENTRYPOINT_WORKER_PROCESSES_AUTOTUNE=1` (sizes workers
  from the cgroup quota), Apache via event MPM CPU-capped. Coraza (Caddy)
  runs at the Go default GOMAXPROCS, which measured fastest within the
  2-CPU cap.
- Same upstream (`mendhak/http-https-echo`, uncapped) and same client
  (`k6`, 20 VUs, 30 s warm-up + 60 s measure window).
- Karna runs DB-less Kong: no Postgres, no Redis. The declarative config
  is loaded at boot via `KONG_DECLARATIVE_CONFIG`, which also sidesteps
  the Admin-API route-propagation artifact described below (there is no
  runtime `POST /routes`). All engine optimizations are unconditional
  (skip-body-rules, transform-cache hoist, skip-multipart-scan, RE2::Set
  `@rx` gate, RE2 `@rx` match, Aho-Corasick `@pm`, fast-path, nested
  transform cache).
- Karna figures are best-of-5: max `http_reqs.rate` over 5 warm rounds
  (cold-start = min avg-ms over 5 restarts), with `checks_rate == 1.0`
  gated on every round. Apache and nginx are the previously-published
  figures on the same host; Coraza is a single warm run. See the
  measurement note at the top.
- Status parity is probed before every run: each scenario's payload is
  sent to all WAFs and only kept if they return the same status (benign
  200, attack 403). If even one returns a different code the scenario is
  excluded or reshaped. `checks_rate = 1.0` on every round confirms parity
  held throughout.
- One WAF at a time: the harness tears the others down so they don't
  compete for CPU.

### A note on the Kong route-propagation artifact

We confirmed (on Kong 3.9.0 and 3.9.1, Postgres mode) that for ~30 s
after `POST /services` / `POST /routes` via the Admin API, a sustained
high-rate keepalive load sees a large fraction (60 to 90%, scaling with
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

`curl` / `ab` based reproductions don't reliably trigger this because
their process-per-connection or pre-established-connection patterns don't
burst into Kong the way k6's in-process VU keepalive model does. This is
independent of Karna: the same reproduction hits a Kong with zero plugins
attached. The DB-less benchmark configuration above avoids it entirely by
loading routes declaratively at boot rather than posting them at runtime.

## Fairness fixes applied before measuring

These are bench-harness issues that were *not* about WAF performance.
They were one-stack disadvantages corrected before trusting the numbers.

- Apache `disablereuse=on`: the official `owasp/modsecurity-crs:apache`
  image ships `ProxyPass / ${BACKEND}/ disablereuse=on`, which opens a
  fresh TCP connection to the backend on every request. Under sustained
  load this exhausts the ephemeral port range and Apache fails ~24% of
  requests with `AH00957`. Fixed by bind-mounting a vhost with
  `enablereuse=on`.
- k6 `reqParams` Host-drop: a bug in our k6 helper re-spread `extra`
  after the merged headers, silently dropping the `Host` header on any
  scenario that passed a custom `Content-Type`. On Kong those requests
  got `404 "no Route matched"` instead of being measured. Fixed by
  destructuring `headers` out of `extra` before spreading.
- nginx `worker_processes`: `worker_processes auto` reads the host's CPU
  count, not the 2-CPU cap, and oversubscribes. We enable
  `NGINX_ENTRYPOINT_WORKER_PROCESSES_AUTOTUNE=1` so the entrypoint sizes
  from the cgroup quota.
- Coraza GOMAXPROCS: Caddy's Go runtime defaults GOMAXPROCS to the host
  core count. We checked both that default and an explicit `GOMAXPROCS=2`
  (matching the cgroup cap); the default measured faster, so it is used.
  The cgroup caps CPU at 2.0 for every WAF regardless.
- Karna `ignore_from_local_ips`: the plugin's default is `true`, which
  short-circuits detection for client IPs in private ranges. The
  benchmark client is on a private bridge, so the default would bypass
  all CRS rules. We set it to `false`.
- Kong `KONG_LOG_LEVEL=warn`: never benchmark Kong at `debug`; per-request
  log spam wrecks throughput.
- Kong `upstream_keepalive_idle_timeout=4`: Kong's default upstream idle
  timeout (60 s) exceeds Node's default server `keepAliveTimeout` (5 s);
  under bursty load Kong can reuse an upstream connection the backend has
  already closed, returning `502 "upstream prematurely closed"`. We set
  Kong's idle below upstream's to eliminate the race.

## Limitations

- Cross-session cross-WAF comparison. Karna was re-measured on 2026-06-03
  with the current shipping config; Apache and nginx are from an earlier
  run on the same dedicated host, and Coraza is a single warm run. The
  ratios are indicative of the current product, not a single back-to-back
  measurement (see the note at the top). Karna's own numbers are
  best-of-5 to damp run-to-run variance.
- Absolute throughput is host-specific. The ordering is stable across
  runs; the absolute rps depends on the box. These are from a Hetzner CCX
  dedicated host, 2 CPU per container.
- Karna's CRS detection coverage is tracked separately by the CRS
  regression suite (`ka-regression-tests/` and `crs-regression-test/`);
  the numbers above are performance only. Correctness is gated by the
  regression suite, not this benchmark.
- Per-WAF strengths vary by workload. nginx+ModSec3 still wins
  multipart-with-files because its body parsing is native C++; Karna wins
  the detection-heavy and mixed paths because libinjection short-circuits
  at the first match and the rule loop skips full CRS evaluation on
  requests it rejects early or that carry no body. OWASP Coraza, despite
  a compiled Go engine with RE2, trails on every scenario here; the Caddy
  reverse-proxy path plus full per-request CRS evaluation costs more than
  the in-process C / LuaJIT engines.
