# Karna recipes

Concrete tasks. Each assumes Karna is already attached to a service (see
`deploy.md`). Add rules as JSON strings to the plugin's `rules_request` array —
every custom rule goes there regardless of phase; the engine runs each in the
phase named by its `phase` field (`access` or `header_filter`). Config-level
overrides tune the CRS pack.

## Turn on blocking (after tuning)
Only after the audit log is clean in detection-only:
```sh
curl -X PATCH http://localhost:8001/plugins/<plugin_id> \
  -d config.engine_blocking_mode=true
```
Then re-send a known-bad request and confirm the 403.

## Block a specific attack on one parameter
```json
{ "id": "blk-sqli-q", "phase": "access",
  "conditions": [ { "op": "libinjection_sqli", "value": "", "transform": ["urlDecodeUni"],
                    "variables": ["request.arg.value:q"] } ],
  "action": { "fixed_response": { "status_code": 403, "body": "Forbidden\r\n" } },
  "message": "SQLi in q", "tags": ["attack-sqli"] }
```

## Sanitize instead of block (false-positive killer)
Strip dangerous characters in place and let the request through:
```json
{ "id": "san-name", "phase": "access", "log": true,
  "conditions": [ { "op": "rx", "transform": [], "value": "[<>\"'&;]",
                    "variables": ["request.arg.value:name"] } ],
  "action": { "fix_matched_parts": { "remove_chars_pattern": "[<>\"'&;]" } },
  "tags": ["sanitize"] }
```

## Rate-limit an endpoint
Needs Redis (`redis_host`/`redis_port`). Caps per source IP:
```json
{ "id": "rl-login", "phase": "access",
  "conditions": [ { "op": "beginsWith", "value": "/api/login", "transform": [],
                    "variables": ["request.raw_path"] } ],
  "action": { "rate_limit": { "key": "%{remote_addr}", "limit": 5, "window_seconds": 60,
              "response": { "status_code": 429, "body": "Too many attempts.\r\n" } } },
  "tags": ["ratelimit"] }
```

## Distributed auto-ban (write + inspect, cluster-wide)
Needs Redis and `redis_inspect_enabled=true`. One rule bans the source on an attack;
a second blocks every request from a banned IP, on every node. Ban write is
fire-and-forget; the read fails open (`redis_on_error=skip`) if Redis is down.
```json
{ "id": "ban-on-sqli", "phase": "access",
  "conditions": [ { "op": "libinjection_sqli", "value": "", "transform": ["urlDecodeUni"],
                    "variables": ["request.arg.value"] } ],
  "action": { "redis_set": { "key": "ban:%{remote_addr}", "value": "1", "expire": 600 },
              "fixed_response": { "status_code": 403, "body": "Forbidden\r\n" } },
  "message": "SQLi — ban 10 min", "tags": ["attack-sqli"] }
```
```json
{ "id": "block-banned", "phase": "access",
  "conditions": [ { "op": "isSet", "value": "", "variables": ["redis.ban:%{remote_addr}"] } ],
  "action": { "fixed_response": { "status_code": 403, "body": "Forbidden\r\n" } },
  "message": "source is banned", "tags": ["banlist"] }
```

## Rate-limit / ban on repeated failed attempts (detected in the response)
A failed login or failed auth looks legitimate in the request — a well-formed
POST with credentials — so you cannot key on the request alone. Detect the
failure in the *response*, count it per source in Redis, then block on the next
request once the count crosses a threshold. This is the generic "lock out an IP
after N bad logins" pattern and works for any endpoint with a distinct failure
response.

Needs Redis and `redis_inspect_enabled=true` (the threshold read is off by
default). `redis_incr_key` needs both `key` and `expire`; the TTL is set on the
first failure and not refreshed, so the counter is a fixed window that resets
`expire` seconds after the first failure. The terminal block only fires in
blocking mode.

Count the failures (response phase). Most APIs answer a bad login with 401/403:
```json
{ "id": "authfail-count", "phase": "header_filter",
  "conditions": [ { "op": "beginsWith", "value": "/login", "variables": ["request.raw_path"] },
                  { "op": "eq", "value": "401", "variables": ["response.status"] } ],
  "action": { "redis_incr_key": { "key": "authfail:%{remote_addr}", "expire": 900 } },
  "message": "failed auth", "tags": ["auth", "bruteforce"] }
```
Block once over the threshold (access phase, so a banned source never reaches
the backend):
```json
{ "id": "authfail-block", "phase": "access",
  "conditions": [ { "op": "beginsWith", "value": "/login", "variables": ["request.raw_path"] },
                  { "op": "gt", "value": "5", "variables": ["redis.authfail:%{remote_addr}"] } ],
  "action": { "fixed_response": { "status_code": 429, "body": "Too many failed attempts.\r\n",
              "headers": { "Retry-After": "900" } } },
  "message": "auth brute-force throttled", "tags": ["auth", "bruteforce", "ban"] }
```
The failure signal is app-specific. Some apps never return 401: WordPress
re-renders the login form with 200 on failure and answers success with 302 plus
a `wordpress_logged_in` cookie, so key on a POST that comes back 200 instead —
swap the counting rule's conditions for:
```json
"conditions": [ { "op": "eq", "value": "POST", "variables": ["request.method"] },
                { "op": "beginsWith", "value": "/wp-login.php", "variables": ["request.raw_path"] },
                { "op": "eq", "value": "200", "variables": ["response.status"] } ]
```
For a ban that outlives the counter window, replace the block action with
`redis_set` (`{ "key": "ban:%{remote_addr}", "expire": 3600 }`) on the threshold
and reuse the `block-banned` rule above.

## Reject a revoked credential from a shared set
Needs `redis_inspect_enabled=true`. A sibling plugin (or your auth service) keeps a
Redis SET `revoked_tokens`; this blocks any request whose `Authorization` header is in it:
```json
{ "id": "blk-revoked", "phase": "access",
  "conditions": [ { "op": "redis_sismember", "value": "%{request_headers.authorization}",
                    "variables": ["redis.revoked_tokens"] } ],
  "action": { "fixed_response": { "status_code": 401, "body": "Token revoked\r\n" } },
  "tags": ["auth"] }
```

## Tame a CRS false positive — three escalating options

1. **Sanitize the whole family instead of blocking** (best when the rules are right
   but blocking is too harsh). Config-level:
   ```json
   { "selector": { "tags": ["attack-xss"] },
     "action": { "type": "fix", "remove_chars_pattern": "[<>\"'&;]" } }
   ```
   Put it in `rule_action_overrides`.

2. **Drop one FP-prone target from a rule** (e.g. libinjection firing on
   `User-Agent`). In the rule's `rule_control`:
   ```json
   { "remove_variable_rx": { "name": "request.header.value",
       "rx": ".*(?:[Uu]ser\\-[Aa]gent|[Rr]eferer|[Aa]uthorization).*" } }
   ```

3. **Disable a specific rule for this service** (last resort):
   ```json
   { "selector": { "ids": ["941110"] }, "action": { "type": "passthrough" } }
   ```
   Put it in `rule_action_overrides`. Prefer 1 or 2 — disabling loses coverage.

## Custom-block response (status / body / headers)
Use `rule_response_overrides` to change what a block returns. `body` is a
static string served verbatim — no `%{var}` macros, so request data is never
reflected into the block response:
```json
{ "selector": { "tags": ["attack-sqli"] },
  "response": { "status_code": 451, "body": "Request refused.",
                "headers": { "x-blocked-by": "waf" } } }
```

## Signal a sibling plugin (skip downstream behaviour)
```json
{ "id": "trust-internal", "phase": "access",
  "conditions": [ { "op": "beginsWith", "value": "/internal/", "variables": ["request.raw_path"] } ],
  "action": { "set_variable": { "name": "skip_js_challenge", "value": true, "type": "shared" } },
  "log": false }
```

## Run the CRS regression locally (do this after any rule/engine change)
```sh
# bring up the dev stack (Postgres + echo + live plugin reload)
docker compose -f docker/docker-compose.dev.yml up -d --build
# fetch the CRS test YAMLs and configure Kong at PL1
cd crs-regression-test && ./fetch-tests.sh && PARANOIA=1 ./configure-kong.sh
# run; compare the pass count to the prior baseline
python3 start.py --testfile tests/ | tee regression.log
grep -E 'Passed tests:' regression.log
```
A drop in the pass count is a regression — investigate before shipping.

## Read the audit log
Default `auditlog_path`: `/usr/local/openresty/nginx/logs`. Karna writes JSON
Lines, one file per worker per minute named
`karna_auditlog_<worker_id>_<YYYYMMDDHHMM>.jsonl` (UTC minute), appending one
record per line. To watch live, tail the newest file, e.g.
`tail -F "$(ls -t karna_auditlog_*.jsonl | head -1)"`. v2 format = one JSON
entry per request with all matches in a `matches` array. `action` values to look
for: `"blocked"`, `"sanitized"`, `"rate_limited"`, `"log"`.

## Debugging "why was this blocked with everything off?"
The always-on gates (allowed methods, path char limits, denied headers,
content-type/charset, arg count) run regardless of `engine_blocking_mode` and the
CRS toggles. Check those config values first. See `configuration.md`.
