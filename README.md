# Karna

A WAF (Web Application Firewall) plugin for Kong Gateway. OWASP CoreRuleSet
compatible, with first-class support for custom local rules, virtual
patching, and ModSecurity-style rule controls.

Karna inspects every request against a layered rule pipeline:

1. **Always-on validation gates** — method allow-list, path-character
   policy, header deny-list, content-type / charset allow-list. These run
   before any rule and apply unconditionally to any request that has
   Karna attached.
2. **Per-service rule controls** (`rules_request` of type rule-control) —
   adjust, exclude, or rewrite global rules at request time. Includes the
   in-repo CRS-fix layer (`coreruleset_fix.lua`) that neutralises known
   false-positive-prone OWASP CRS rules in production deployments.
3. **Per-service local rules** (`rules_request`, `rules_response`) — your
   own custom rules. Gated by `local_rules_enabled` (default `true`).
4. **OWASP CoreRuleSet** loaded from disk at `init_worker`. Gated by
   `coreruleset_enabled` (default `true`).

Detection-only or blocking is controlled by `engine_blocking_mode`
(default `false` — detection-only).

Karna is also **MCP-aware** (Model Context Protocol) — request-side
detection and parsing of the JSON-RPC envelope, plus SSE response
reassembly with per-event rule evaluation on the Streamable HTTP
transport. See the `mcp_*` configuration fields below.

## Installation

Three pieces need to be on the Kong / OpenResty host.

### 1. The plugin itself

Install via LuaRocks from the cloned repo:

```sh
git clone https://github.com/sicuranext/karna.git
cd karna
luarocks make
```

Runtime deps declared in the rockspec (`lua-resty-http`, `lua-zlib`,
`inspect`) are pulled in automatically. `lua-zlib` requires `zlib1g-dev`
at compile time. On Kong base images, `inspect` is already pre-installed.

### 2. `libinjection.so`

Native library used for SQLi / XSS detection via FFI.

```sh
git clone --branch v3.10.0 https://github.com/client9/libinjection.git
cd libinjection/src
gcc -shared -fPIC -O2 -o /usr/local/lib/libinjection.so \
    libinjection_sqli.c libinjection_xss.c libinjection_html5.c
ldconfig
```

The path is overridable via the env var `KARNA_LIBINJECTION_SO`
(default `/usr/local/lib/libinjection.so`).

### 3. OWASP CoreRuleSet

```sh
mkdir -p /opt/coreruleset
curl -fsSL https://github.com/coreruleset/coreruleset/archive/refs/tags/v4.26.0.tar.gz \
  | tar -xz --strip-components=1 -C /opt/coreruleset
```

The path is overridable via the env var `KARNA_CRS_PATH` (default
`/opt/coreruleset/rules/`). Trailing slash auto-normalized.

> **Note**: env vars must be whitelisted in nginx's `main` context for the
> worker processes to see them. With Kong, do this via
> `KONG_NGINX_MAIN_INCLUDE` pointing at a snippet such as:
>
> ```
> env KARNA_CRS_PATH;
> env KARNA_LIBINJECTION_SO;
> ```
>
> See `docker/kong/main-env.conf` in this repo for the working reference.

### Enable the plugin in Kong

In `kong.conf`:

```
plugins = bundled,karna
```

…then `kong reload`.

## Local development / integration test stack

A turnkey Docker Compose stack is in this repo: Postgres + Redis + Kong
(with libinjection + CRS pre-installed) + an HTTP echo upstream.

```sh
docker compose up --build
```

See [`docker/README.md`](./docker/README.md) for the quickstart and the
hurl integration test commands.

## Attaching the plugin to a Kong service

```sh
curl -X POST http://localhost:8001/services/<service_id>/plugins \
  -H "Content-Type: application/json" \
  -d '{
    "name": "karna",
    "enabled": true,
    "config": {
      "engine_blocking_mode": true,
      "paranoia_level": 1,
      "auditlog_enabled": true,
      "auditlog_path": "/usr/local/openresty/nginx/logs",
      "redis_host": "localhost"
    }
  }'
```

## Configuration

| Field | Type | Default | Description |
|---|---|---|---|
| `engine_blocking_mode` | bool | `false` | If `true`, matched rules return their `fixed_response` action (typically 403). If `false`, matches are logged only. |
| `coreruleset_enabled` | bool | `true` | Toggle for the OWASP CRS rule pack loaded from disk at `init_worker`. The in-repo CRS-fix rule controls (`coreruleset_fix.lua`) are always applied. |
| `local_rules_enabled` | bool | `true` | Toggle for `rules_request` / `rules_response` local rules. |
| `ignore_from_local_ips` | bool | `true` | Skip WAF for clients in `127.0.0.0/8`, `192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`, `::1`, `fe80::/32`. |
| `paranoia_level` | number | `1` | OWASP CRS paranoia level (1–4). Rules tagged paranoia-level/3 or /4 are skipped at parse time when below this level. |
| `set_karna_headers` | bool | `false` | Set `X-Karna-Engine` / `X-Karna-Engine-Version` response headers. |
| `request_methods_allowed` | array | `[GET, HEAD, PUT, POST, DELETE, OPTIONS, PATCH, PROPFIND]` | Method allow-list. |
| `request_headers_denied` | array | `[content-encoding, proxy, lock-token, content-range, if]` | Request header deny-list. |
| `request_content_type_allowed` | array | `[application/x-www-form-urlencoded, multipart/form-data, multipart/related, text/xml, application/xml, application/soap+xml, application/json, application/cloudevents+json, application/cloudevents-batch+json]` | Content-Type allow-list. |
| `request_content_type_charset_allowed` | array | `[utf-8, iso-8859-1, iso-8859-15, windows-1252]` | Content-Type charset allow-list. |
| `restricted_extensions` | array | (long list — see `schema.lua`) | Forbidden file extensions in path. |
| `check_invalid_chars_in_path` | bool | `false` | Block paths containing invalid characters. |
| `limit_invalid_chars_in_path` | number | `1` | Threshold for the above. |
| `check_special_chars_in_path` | bool | `true` | Block paths with too many special characters. |
| `limit_special_chars_in_path` | number | `3` | Threshold for the above. |
| `total_arg_value_length` | number | `64000` | Max combined length of all arg values in a request. |
| `limit_arg_name_length` | number | `100` | Max length of a single arg name. |
| `limit_arg_value_length` | number | `400` | Max length of a single arg value. |
| `limit_arg_num` | number | `255` | Max number of args. |
| `try_bas64decode_if_possible` | bool | `false` | Attempt base64 decoding of arg values before inspection. |
| `rules_request` | array of stringified-JSON | — | Per-service local rules for the access / header_filter phase, including rule controls. |
| `rules_response` | array of stringified-JSON | — | Per-service local rules for the response inspection. |
| `auditlog_enabled` | bool | `true` | Write JSON audit logs. |
| `auditlog_path` | string | `/usr/local/openresty/nginx/logs` | Audit log directory (must be writable by the Kong worker user). |
| `auditlog_format` | string | `v2` | `v1` (legacy, ModSecurity-compatible when `auditlog_modsec=true`) or `v2` (per-request, all matches in `matches[]`). |
| `auditlog_only_on_match` | bool | `false` | Only write audit log when at least one rule matched. |
| `auditlog_modsec` | bool | `false` | v1 only — emit ModSecurity-compatible format. |
| `auditlog_error_log_on_match` | bool | `false` | Mirror matched rules to nginx error log. |
| `redis_host` | string | `localhost` | Redis host for counter-based rules. |
| `redis_port` | number | `6379` | Redis port. |
| `redis_password` | string | — | Redis AUTH (optional). |
| `private_debug` | bool | `false` | Verbose debug output. |

### Environment variables

| Name | Default | Purpose |
|---|---|---|
| `KARNA_CRS_PATH` | `/opt/coreruleset/rules/` | Override the CRS rules directory. |
| `KARNA_LIBINJECTION_SO` | `/usr/local/lib/libinjection.so` | Override the libinjection shared object path. |

Both are read at `init_worker` time and must be exposed to nginx workers
via `env <NAME>;` directives in the main context.

## Rule Variables

| Variable name | Description | Example |
| --- | --- | --- |
| `request.cookie.value` | Array of cookie values | `Cookie: a=foo; b=bar` → `["foo", "bar"]` |
| `request.cookie.name` | Array of cookie names | `Cookie: a=foo; b=bar` → `["a", "b"]` |
| `request.arg.value` | Array of values from querystring + parsed body | `?a=foo` + JSON body `{"b":"bar"}` → `["foo", "bar"]` |
| `request.arg.name` | Array of keys from querystring + parsed body | `?a=foo` + JSON body `{"b":"bar"}` → `["a", "b"]` |
| `request.query.value` | Array of values from the querystring | `?a=foo&b=bar` → `["foo", "bar"]` |
| `request.query.name` | Array of keys from the querystring | `?a=foo&b=bar` → `["a", "b"]` |
| `matched.value` | Value matched by the `rx` operator | — |
| `request.header.value` | Array of request header values | `User-Agent: foobar` → `["foobar"]` |
| `request.header.name` | Array of request header names | `User-Agent: foobar` → `["user-agent"]` |
| `request.file` | Filename or multipart param name | `-F image=@/x/test.jpg` → `["test.jpg"]` |
| `request.body.multipart.filename` | Multipart filenames | — |
| `request.body.multipart.combined_size` | Size of all parts | — |
| `request.body.multipart.header.value` | Multipart header values | — |
| `request.raw_path` | Path component, not normalized, no querystring | `/t/Abc%20123/parent/..//test/./` |
| `request.basename` | Last segment of the path | `/index.php?a=b` → `index.php` |
| `response.set_cookie.name` | Array of cookie names from `Set-Cookie` | — |
| `response.set_cookie.value` | Array of cookie values from `Set-Cookie` | — |

## Referer Request Header

| Variable name | Description |
| --- | --- |
| `request.header.referer.path` | Path component of the Referer URL |
| `request.header.referer.query` | Full query string of the Referer URL |
| `request.header.referer.scheme` | Scheme of the Referer URL |
| `request.header.referer.host` | Host of the Referer URL |
| `request.header.referer.query.name:<id>` | Referer query parameter name |
| `request.header.referer.query.value:<id>` | Referer query parameter value |

## Special Rule Variables

| Variable | Description |
| --- | --- |
| `request.header_no_fp.value` | Request headers excluding the most FP-prone ones (User-Agent, Referer, …) |

## Rule Schema

```json
{
    "id": "1234",
    "phase": "access",
    "conditions": [
        {
            "multi_match": false,
            "op": "rx",
            "transform": ["urlDecodeUni"],
            "value": "['\"`]+.*['\"`;&|]+",
            "variables": ["request.arg.value"]
        },
        {
            "multi_match": false,
            "op": "ge",
            "value": "1",
            "variables": ["var:paranoia_level"]
        }
    ],
    "action": {
        "fix_matched_parts": {
            "remove_chars_pattern": "[\"';&|`]*"
        }
    },
    "log": true,
    "message": "Foo bar",
    "tags": ["injection", "virtual-patching"]
}
```

## False Positives — taming libinjection

LibInjection on request headers is prone to false positives — `User-Agent`
and `Referer` strings often look SQLi-shaped to it. To carve out exceptions,
use `remove_variable_rx` rule controls:

```json
{
    "id": "2201",
    "phase": "access",
    "conditions": [
        {
            "multi_match": false,
            "op": "libinjection_sqli",
            "transform": ["urlDecodeUni"],
            "value": "",
            "variables": ["request.header.value"]
        }
    ],
    "action": {
        "fixed_response": {
            "status_code": 403,
            "headers": {
                "content-type": "text/plain",
                "cache-control": "max-age=0, private, no-store, no-cache, must-revalidate"
            },
            "body": "Forbidden\r\n"
        }
    },
    "message": "SQL Injection: header-borne",
    "rule_control": [
        {
            "remove_variable_rx": {
                "name": "request.header.value",
                "rx": ".*(?:[Uu]ser\\-[Aa]gent|[Rr]eferer|[Aa]ccept.*|[Cc]ontent.*|[Ss]ec\\-|[Aa]uthorization).*"
            }
        }
    ],
    "tags": ["injection", "attack-sqli"]
}
```

## Rule Control Functions

### `change_rule_action`

```json
"rule_control": [
    {
        "change_rule_action": {
            "rule_id": "1234",
            "action": {
                "fixed_response": {
                    "status_code": 200,
                    "headers": {
                        "content-type": "text/plain",
                        "cache-control": "max-age=0, private, no-store, no-cache, must-revalidate"
                    },
                    "body": "Hello!\r\n"
                }
            }
        }
    }
]
```

### `change_condition_tfunc`

```json
"rule_control": [
    {
        "change_condition_tfunc": {
            "rule_id": "1234",
            "condition_number": 1,
            "new_tfunc": ["lowercase","hexSequenceDecode"]
        }
    }
]
```

### `change_condition_value`

```json
"rule_control": [
    {
        "change_condition_value": {
            "rule_id": "1234",
            "condition_number": 1,
            "new_value": "^/f[o]+bar"
        }
    }
]
```

### `replace_condition`

```json
"rule_control": [
    {
        "replace_condition": {
            "rule_id": "1234",
            "condition_number": 1,
            "new_condition": {
                "multi_match": false,
                "op": "!isSet",
                "transform": [],
                "value": "",
                "variables": [ "request.header.value:content-type" ]
            }
        }
    }
]
```

### `remove_condition`

```json
"rule_control": [
    {
        "remove_condition": {
            "rule_id": "1234",
            "condition_number": 1
        }
    }
]
```

### `add_condition`

```json
"rule_control": [
    {
        "add_condition": {
            "rule_id": "1234",
            "condition": {
                "multi_match": false,
                "op": "!isSet",
                "transform": [],
                "value": "",
                "variables": [ "request.header.value:content-type" ]
            }
        }
    }
]
```

### `remove_rule`

```json
"rule_control": [
    { "remove_rule": { "rule_id": "1234" } }
]
```

### `remove_variable_from_rule_conditions`

```json
"rule_control": [
    {
        "remove_variable_from_rule_conditions": {
            "rule_id": "1234",
            "variable_name": "request.header.value"
        }
    }
]
```

### `remove_rules_by_tag`

```json
"rule_control": [
    { "remove_rules_by_tag": { "tag": "injection" } }
]
```

### `remove_target_rule_by_pattern`

```json
"rule_control": [
    {
        "remove_target_rule_by_pattern": {
            "rule_id": "1234",
            "pattern": ".*[:]param[0-9]$"
        }
    }
]
```

### `remove_target_tag_by_pattern`

```json
"rule_control": [
    {
        "remove_target_tag_by_pattern": {
            "tag": "attack-sqli",
            "pattern": ".*[:]password$"
        }
    }
]
```

## Custom log fields

```json
{
    "id": "local_123",
    "phase": "header_filter",
    "conditions": [
        { "op": "beginsWith", "value": "/login", "variables": ["request.raw_path"] },
        { "op": "eq", "value": "POST", "variables": ["request.method"] },
        { "op": "isSet", "value": "", "variables": ["request.body.urlencode.value:username"] },
        { "op": "isSet", "value": "", "variables": ["request.body.urlencode.value:password"] },
        { "op": "isSet", "value": "", "variables": ["response.header.name:set-cookie"] },
        { "op": "isSet", "value": "", "variables": ["response.set_cookie.name:session"] }
    ],
    "action": {
        "set_log_fields": [
            { "name": "username", "value": "%{request.body.urlencode.value:username}" }
        ]
    },
    "log": false
}
```

## External plugin logging

Any sibling Kong plugin can record its own log events through Karna's audit
log v2, without emitting a sentinel response header or running its own
file writer. This avoids the common "two log pipelines" problem when Karna
sits in a plugin chain.

A sibling plugin appends entries to `kong.ctx.shared.karna.log_entries`
during any phase before `log`:

```lua
kong.ctx.shared.karna             = kong.ctx.shared.karna             or {}
kong.ctx.shared.karna.log_entries = kong.ctx.shared.karna.log_entries or {}

table.insert(kong.ctx.shared.karna.log_entries, {
    source   = "my-cache-plugin",                    -- string, required
    rule_id  = "cache-stale-served",                 -- string, required
    message  = "Served stale entry while revalidating", -- string, required
    tags     = { "cache", "stale-while-revalidate" },   -- optional array
    metadata = {                                        -- optional table
        cache_key   = "...",
        ttl_seconds = 60
    }
})
```

Karna picks these up in the `log` phase and emits them under
`external_matches[]` in the audit log v2 entry:

```json
{
    "version": "2.0",
    "matches": [],
    "external_matches": [
        {
            "source": "my-cache-plugin",
            "rule_id": "cache-stale-served",
            "message": "Served stale entry while revalidating",
            "tags": ["cache", "stale-while-revalidate"],
            "metadata": { "cache_key": "...", "ttl_seconds": 60 }
        }
    ]
}
```

Behaviour notes:

- The presence of one or more `external_matches` is enough to make Karna
  write the audit log entry even when no Karna rule matched. So
  `auditlog_only_on_match = true` still emits a record when a sibling
  plugin logged something.
- Malformed entries (missing `source` / `rule_id` / `message`, or wrong
  types) are silently dropped — one bad caller cannot break the audit log
  for the rest of the request.
- `source`, `rule_id` and `message` are clipped at 100 / 100 / 1000 bytes
  respectively. `tags` and `metadata` are passed through unchanged.
- `external_matches` is a v2-only feature. The v1 (ModSecurity-compatible)
  format is unaffected.

## Redis actions

### Increment a counter on a failed login

```json
{
    "id": "local_123",
    "phase": "header_filter",
    "conditions": [
        { "op": "beginsWith", "value": "/login", "variables": ["request.raw_path"] },
        { "op": "eq", "value": "POST", "variables": ["request.method"] },
        { "op": "isSet", "value": "", "variables": ["request.body.urlencode.value:username"] },
        { "op": "isSet", "value": "", "variables": ["request.body.urlencode.value:password"] },
        { "op": "!isSet", "value": "", "variables": ["response.set_cookie.name:session"] }
    ],
    "action": {
        "redis_incr_key": {
            "key": "failed_login_attempts_%{request.header.value:host}_%{remote_addr}",
            "expire": 300
        }
    },
    "log": false
}
```

### Block when the counter exceeds a threshold

```json
{
    "id": "local_124",
    "phase": "access",
    "conditions": [
        {
            "op": "ge",
            "value": "2",
            "variables": ["redis.key:failed_login_attempts_%{request.header.value:host}_%{remote_addr}"]
        }
    ],
    "action": {
        "fixed_response": {
            "status_code": 403,
            "headers": {
                "content-type": "text/plain",
                "cache-control": "max-age=0, private, no-store, no-cache, must-revalidate"
            },
            "body": "Too many login attempts.\r\n"
        }
    },
    "log": false
}
```

## License

Apache-2.0 © SicuraNext s.r.l.
