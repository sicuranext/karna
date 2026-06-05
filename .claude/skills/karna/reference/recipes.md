# Karna recipes

Concrete tasks. Each assumes Karna is already attached to a service (see
`deploy.md`). Add rules as JSON strings to the plugin's `rules_request` /
`rules_response` arrays, or use config-level overrides for the CRS pack.

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
Use `rule_response_overrides` to change what a block returns:
```json
{ "selector": { "tags": ["attack-sqli"] },
  "response": { "status_code": 451, "body": "Refused: %{request.remote_addr}",
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
Default `auditlog_path`: `/usr/local/openresty/nginx/logs`. v2 format = one JSON
entry per request with all matches in a `matches` array. `action` values to look
for: `"blocked"`, `"sanitized"`, `"rate_limited"`, `"log"`.

## Debugging "why was this blocked with everything off?"
The always-on gates (allowed methods, path char limits, denied headers,
content-type/charset, arg count) run regardless of `engine_blocking_mode` and the
CRS toggles. Check those config values first. See `configuration.md`.
