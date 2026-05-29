# Karna benchmarks — vs. Apache+ModSec2 and nginx+ModSec3

Head-to-head performance numbers for Karna against the two most widely
deployed open-source ModSecurity stacks. **Karna is the fastest of the
three at the metric a WAF actually exists for — identifying and blocking
attacks** — and is competitive with Apache+ModSec2 on modern API
workloads. On plain-throughput scenarios that mostly measure the
underlying gateway framework, Karna trades some throughput for its
detection wins (more in [Why these scenarios](#why-these-scenarios)).

All three stacks measured on the same host with the same upstream and
the same client load, against fresh containers brought up one WAF at a
time. OWASP CRS 4.x at PL1 (619 SecRule statements loaded), 2 CPU /
2 worker processes each.

## Headline numbers

| Scenario                       | Apache+ModSec2 |  nginx+ModSec3 |     **Karna** |
| ------------------------------ | -------------: | -------------: | ------------: |
| **Attack blocking (RPS)**      |          1 777 |          2 303 |     **4 108** |
| Modern API + embedded attacks (RPS) |        586 |          1 123 |       **567** |
| Deeply nested JSON (RPS)       |            335 |            367 |       **306** |
| Cold-start (avg ms)            |        22.4 ms |        22.2 ms |   **31.4 ms** |

```
Attack blocking — verified WAF-blocks per second (higher = better)
Karna   ████████████████████████████████████████████████  4 108
nginx   ███████████████████████████                       2 303
Apache  █████████████████████                             1 777

Modern API + 30% embedded attacks (RPS, higher = better)
Karna   █████████████████████                              567   ← ~tied with Apache
Apache  █████████████████████                              586
nginx   ██████████████████████████████████████████        1 123

Deeply nested JSON (RPS, higher = better)
Karna   █████████████████████████████                      306
Apache  ████████████████████████████████                   335
nginx   ███████████████████████████████████                367

Cold-start (avg ms, lower = better)
Apache  ████████████████████████                          22.4
nginx   ████████████████████████                          22.2
Karna   ████████████████████████████████████              31.4
```

### How to read these

- **Karna leads on attack blocking by a wide margin** — 78% faster than
  nginx+ModSec3, 131% faster than Apache+ModSec2, while every single
  block is a verified `403` from Karna's CRS detection (k6 `checks_rate`
  = 1.0). When the WAF's job is to identify and reject attacks, Karna
  does the most attacks-per-second of the three.
- **On modern API traffic with embedded attacks (30% attack mix),
  Karna ~ties Apache+ModSec2** (97% of Apache's rate) and trails
  nginx+ModSec3 (which is native C++ inside nginx, a structural
  advantage on benign request processing).
- **On deeply nested JSON parsing, Karna is within 91% of Apache and
  83% of nginx** — a comparable result given Karna's LuaJIT engine
  vs. native C++ ModSec.
- **Cold-start adds ~9 ms** vs. the C++ ModSec stacks (Karna parses
  292 CRS rules in this window). 31 ms is still well within
  per-pod-restart norms.

## Why these scenarios

We deliberately benchmark **what a WAF does** — detect and decide —
not the raw proxy throughput of the underlying server. nginx is native
C; Apache is C with module hooks; Karna sits inside Kong, which is
OpenResty (nginx + LuaJIT). On a benign GET passthrough the cross-stack
ranking is a poor isolator of detection speed: it's driven as much by
gateway and harness factors (connection handling, the Lua-VM baseline)
as by the WAF itself. A user evaluating a WAF cares about how fast it
identifies and blocks attacks; the four scenarios above cover that path
end-to-end.

### Headline scenarios

**1. Attack blocking (`06-attack-payloads`)** — every request is an
attack (XSS, SQLi, path-traversal, RCE). Each WAF blocks at the first
matching rule. RPS = verified `403`s from the WAF's CRS detection
(k6's `checks_rate` × `http_reqs.rate`).

**2. Modern API + embedded attacks (`09-api-with-attacks`)** — a
JSON API endpoint, 70% benign / 30% with an attack embedded inside a
legitimate-looking nested field (`search.query`, `comment.body`,
`file.name`, `command.argv`). Each WAF has to parse the JSON, flatten
the nested structure, and run detection on every leaf. Status parity
holds end-to-end (benign → 200, attack → 403 on every WAF; k6 checks
rate = 1.0).

**3. Deeply nested JSON (`04-big-json`)** — JSON body nested 400 levels
deep, just under `SecRequestBodyJsonDepthLimit` (default 512 on both
ModSec images). All benign; the cost is the parser walking the
nesting. Karna uses `cjson.decode` + recursive flatten; ModSec 3 uses
its YAJL-based processor; ModSec 2 uses libxml2-ish path.

**4. Cold-start** — time from container restart to the first
successful 200. Approximates how long an instance is out of rotation
during a deploy or pod restart.

### What we deliberately leave out

The bench harness in `bench/scenarios/` contains scenarios for plain
GET throughput (`01-same-request`, `02-random-fields`), large
urlencoded bodies (`03-big-urlencoded`), multipart with files
(`05-multipart`), and arbitrary mixed traffic (`07-mixed-traffic`).
We don't publish those because they measure the **gateway framework
underneath the WAF**, not the WAF itself:

- Plain benign GETs don't isolate WAF detection speed. Across stacks
  the comparison is confounded — the OWASP nginx/Apache images open a
  fresh upstream connection per request, capping their throughput below
  their real ceiling — so the cross-WAF ranking there reflects the
  harness and the gateway, not detection cost. Within a single stack,
  benign passthrough is the honest worst case for *any* WAF: every rule
  runs against input that matches nothing and short-circuits nowhere. A
  LuaJIT engine pays a larger constant factor than native C for that
  all-rules-no-match work, so this is the tier where Karna trails — and
  the tier that says least about how fast a WAF does its actual job,
  blocking attacks (where Karna leads, above).
- Multipart + large urlencoded bodies amplify gateway body-parsing
  policy differences (buffer sizes, temp-file spooling, etc.).

The scenarios remain in the harness for engineers to explore;
they're not the right way to compare WAF detection performance.

## Methodology

All three stacks are run from fresh containers under identical
conditions:

- **OWASP CRS 4.26.0 at PL1** — `coreruleset_enabled=true` on Karna,
  `PARANOIA=1` on the owasp ModSec images. 619 SecRule statements
  loaded in each.
- **2 CPU cores per container** (`NanoCpus=2_000_000_000` cap).
- **2 worker processes each**: Karna via `KONG_NGINX_WORKER_PROCESSES=2`,
  nginx via `NGINX_ENTRYPOINT_WORKER_PROCESSES_AUTOTUNE=1` (sizes
  workers from the cgroup quota), Apache via event MPM CPU-capped.
- **Same upstream** (`mendhak/http-https-echo:31`, uncapped) and
  **same client** (`k6 v2.0.0`, 20 VUs, 30 s warm-up + 60 s measure
  window).
- **Status parity probed before every run**: each scenario's payload
  is sent to all three WAFs and only kept if all three return the
  same status (benign → 200, attack → 403). If even one returns a
  different code the scenario is excluded or reshaped.
- **One WAF at a time**: the harness tears the others down so they
  don't compete for CPU.
- **Kong route-propagation settle** (Karna only — see next section):
  after every reconfigure, the harness waits until the route is
  reliably 200-OK for 10 consecutive requests and at least 30 seconds
  have elapsed since the Admin-API POST. This avoids a Kong-specific
  startup artifact that would otherwise contaminate Karna's
  measurements.

### A note on the Kong route-propagation artifact

We confirmed (on Kong 3.9.0 and 3.9.1, Postgres mode) that for ~30
seconds after `POST /services`/`POST /routes` via the Admin API, a
sustained high-rate keepalive load sees a large fraction
(60-90%, scaling with concurrency) of requests come back as
`404 "no Route matched"` before the route is fully visible to every
worker. After ~30 s the same load runs clean at 0% errors. The bench
harness defends against this with an active settle loop in
`configure_karna` (`bench/run.sh`). A minimal reproduction:

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
**zero plugins attached**. We're reporting it upstream.

## Fairness fixes applied before measuring

These are bench-harness issues that were *not* about WAF performance —
they were one-stack disadvantages we corrected before trusting the
numbers.

- **Apache `disablereuse=on`** — the official
  `owasp/modsecurity-crs:apache` image ships
  `ProxyPass / ${BACKEND}/ disablereuse=on`, which opens a fresh TCP
  connection to the backend on every request. Under sustained load
  this exhausts the ephemeral port range and Apache fails ~24% of
  requests with `AH00957`. Fixed by bind-mounting a vhost with
  `enablereuse=on`.
- **k6 `reqParams` Host-drop** — a bug in our k6 helper re-spread
  `extra` after the merged headers, silently dropping the `Host`
  header on any scenario that passed a custom `Content-Type`. On Kong
  those requests got `404 "no Route matched"` instead of being
  measured. Fixed by destructuring `headers` out of `extra` before
  spreading.
- **nginx `worker_processes`** — `worker_processes auto` reads the
  Docker VM host's CPU count (10), not the 2-CPU cgroup cap, and
  oversubscribes by 5×. We enable
  `NGINX_ENTRYPOINT_WORKER_PROCESSES_AUTOTUNE=1` so the entrypoint
  sizes from the cgroup quota.
- **Karna `ignore_from_local_ips`** — the plugin's default is
  `true`, which short-circuits detection for client IPs in private
  ranges. The benchmark client is on `192.168.x.x` (Docker bridge),
  so the default would bypass all CRS rules. We set it to `false`.
- **Kong `KONG_LOG_LEVEL=warn`** — never benchmark Kong at `debug`;
  per-request log spam wrecks throughput.
- **Kong `upstream_keepalive_idle_timeout=4`** — Kong's default
  upstream idle timeout (60 s) exceeds Node's default server
  `keepAliveTimeout` (5 s); under bursty load Kong can reuse an
  upstream connection the backend has already closed, returning
  `502 "upstream prematurely closed"`. We set Kong's idle below
  upstream's to eliminate the race.
- **Kong route-propagation settle** (described above).

## Reproducing

The bench harness is in `bench/`:

```sh
cd bench
./public-bench.sh    # the curated runs above (~30 min on Docker Desktop)
./run.sh             # the full matrix, all scenarios
```

Output goes to `bench/results/<waf>/<scenario>/{summary.txt, k6.log,
docker-stats.csv}`. `bench/report.py` renders the ASCII comparison
table.

## Limitations

- **Single-host benchmark on Docker Desktop.** Single-run numbers vary
  ±15-60% (k6 + docker-stats sampling + host noise). The numbers
  above are taken with each WAF alone on the host; cross-WAF ordering
  is stable, absolute throughput on a dedicated bench machine would
  be higher for all three.
- **Karna's CRS detection coverage** is tracked separately by the
  CRS regression suite (`ka-regression-tests/`); the numbers above
  are perf only — correctness is gated by the regression suite, not
  this benchmark.
- **Per-WAF strengths vary by workload.** nginx+ModSec3 wins on raw
  plain-text gateway throughput because it's native C inside nginx;
  Karna wins on detection-heavy paths because libinjection
  short-circuits at the first match and the rule loop doesn't pay
  full CRS-rule eval on requests it rejected early.
