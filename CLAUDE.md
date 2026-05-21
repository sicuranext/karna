# Karna — CLAUDE.md

## Project Overview

**Karna** (`karna`) is a Lua plugin for Kong Gateway that acts as a
**WAF (Web Application Firewall) engine** compatible with the
**OWASP CoreRuleSet (CRS)**. It runs as a fully self-contained Kong
plugin with no required dependency on other plugins.

## Architecture

### Entry Point
- `kong/plugins/karna/handler.lua` — Kong plugin handler (priority 8300).
  Implements `init_worker`, `access`, `header_filter`, `body_filter`, and `log` phases.
  - On `init_worker`: loads and caches CRS rules (parsed from SecLang `.conf` files) into an LRU cache.
  - On `access`: evaluates rules against the incoming request (rule controls first, then local rules, then global CRS rules).
  - On `log`: writes JSON audit logs to disk asynchronously.

### Schema
- `kong/plugins/karna/schema.lua` — Plugin configuration schema. Key settings:
  - `engine_blocking_mode` (bool): when true, matched rules return 403; otherwise detection-only.
  - `paranoia_level` (number, 1-4): OWASP CRS paranoia level.
  - `coreruleset_enabled` (default true): toggle for the OWASP CRS rule pack loaded from disk at `init_worker`. The in-repo CRS-fix rule controls (`coreruleset_fix.lua`) are always applied independently.
  - `local_rules_enabled`: per-service custom rules.
  - `rules_request` / `rules_response`: per-service JSON rule arrays.
  - `auditlog_enabled`, `auditlog_path`, `auditlog_modsec`: audit logging config.
  - `redis_host`, `redis_port`, `redis_password`: Redis connection for counters.
  - Various request validation limits (arg length, arg count, methods, content types, extensions, charsets).

### Core Modules (in `kong/plugins/karna/modules/`)
- **`ka_engine.lua`** — The rule evaluation engine. Loads CRS rules via `seclang`, resolves variables from the request context, applies transformation functions, runs operators (regex, libinjection, string match, etc.), and evaluates rule chains. This is the largest and most critical module.
- **`seclang.lua`** — SecLang (ModSecurity rule language) parser. Reads OWASP CRS `.conf` files from the path in `seclang.crs_path` (default `/opt/coreruleset/rules/`, override via `KARNA_CRS_PATH` env var). Matches canonical `SecRule <vars> "<op>" "<actions>"` only — `SecRule*` derivatives like `SecRuleUpdateTargetById` (CRS 4.x exception files) are intentionally skipped, not parsed. A defensive guard skips any malformed `SecRule` with a `WARN` print so a single bad rule cannot crash `init_worker`.
- **`ka_body_parser.lua`** — Request body parser. Handles URL-encoded, JSON, multipart, and XML body formats. Flattens nested structures into key-value pairs for rule evaluation. Supports optional base64 decoding. Gzip-encoded bodies require `lua-zlib` (declared in rockspec).
- **`ka_mcp.lua`** — MCP (Model Context Protocol) request-side detection and JSON-RPC envelope parsing. Populates the `mcp.*` variable namespace used by rules and exposes operators `mcp_method_in` and `mcp_jsonrpc_valid`. Brand-neutral (`mcp.*` names are protocol-level, not Karna-branded).
- **`ka_mcp_sse.lua`** — Response-side SSE reassembler for the MCP Streamable HTTP transport. Reconstructs `event:` / `data:` frames, evaluates rules per event in the `mcp_event` phase, and supports streaming actions (drop / replace / terminate / inject).
- **`ka_utils.lua`** — Utility functions: URL decode/encode, base64 decode, UTF-8/hex conversion, audit log generation, Redis operations, URL parsing.
- **`ka_ai.lua`** — OpenAI integration for LLM-based analysis (chat completions).
- **`ka_multipart.lua`** — Custom multipart form-data parser.
- **`libinjection.lua`** — SQL injection and XSS detection via libinjection (FFI-loaded). Path defaults to `/usr/local/lib/libinjection.so`, overridable via `KARNA_LIBINJECTION_SO` env var.
- **`slaxml.lua` / `slaxdom.lua`** — Pure Lua SAX XML parser used for XML body parsing.

### Rules (in `kong/plugins/karna/rules/`)
- **`coreruleset_fix.lua`** — Rule controls that fix/adjust problematic CRS rules in production: removes known false-positive-prone rules, narrows over-broad condition variables. Loaded unconditionally at `init_worker` (no toggle). This is the operational-wisdom layer that makes OWASP CRS deployable without drowning in FPs.

## Key Concepts

- **Rule format**: Rules are Lua tables with `id`, `phase`, `conditions` (array of `{variables, op, value, transform}`), `action`, `message`, `tags`, `paranoia_level`, and optional `rule_control`.
- **Rule controls**: Mechanism to remove rules, remove specific targets from rules, or modify rule conditions at runtime (similar to ModSecurity `ctl:ruleRemoveById`).
- **Operators**: `rx` (regex), `eq`, `gt`, `lt`, `beginsWith`, `endsWith`, `contains`, `pm`/`pmFromFile` (phrase match), `within`, `libinjection_sqli`, `libinjection_xss`, `validateUrlEncoding`, `validateUtf8Encoding`, `validateByteRange`, `ipMatch`.
- **Transformation functions**: `urlDecodeUni`, `lowercase`, `htmlEntityDecode`, etc. — applied to values before operator matching.
- **Variables**: Internal naming convention like `request.arg.value`, `request.header.value:host`, `request.cookie.name`, `request.body`, etc.
- **Phases**: Rules run in Kong phases — `access` (request), `header_filter` (response headers), `body_filter` (response body).

## Language & Runtime
- **Language**: Lua (LuaJIT via OpenResty)
- **Runtime**: Kong Gateway (OpenResty/nginx)
- **Lua dependencies (bundled with OpenResty / Kong)**: `resty.lrucache`, `resty.ipmatcher`, `resty.redis`, `cjson`, `ngx.base64`, `ngx.re`
- **Lua dependencies (declared in rockspec)**: `lua-resty-http`, `lua-zlib`, `inspect`. The dev image installs `lua-zlib` from a direct rockspec URL because the luarocks.org manifest exceeds LuaJIT's 65k-constants limit (`luarocks install lua-zlib` plain fails on Kong's image — see `docker/kong/Dockerfile`).
- **Native dependencies**: `libinjection.so` (system library, FFI-loaded). Default path `/usr/local/lib/libinjection.so`, overridable via `KARNA_LIBINJECTION_SO` env var.
- **Data dependencies**: OWASP CRS rules at `/opt/coreruleset/rules/` (download separately). Override the path with the `KARNA_CRS_PATH` env var (read once at `init_worker` via `modules/seclang.lua`; trailing slash auto-normalized).
- **Env var propagation**: env vars are read with `os.getenv()` from worker processes. nginx wipes the env by default, so any var you want available must be declared in the main context via `env <NAME>;`. With Kong, point `KONG_NGINX_MAIN_INCLUDE` at a snippet such as `docker/kong/main-env.conf`.

## Module Require Paths
Modules use Kong's plugin require convention:
```lua
require "kong.plugins.karna.ka_engine"
require "kong.plugins.karna.ka_seclang"
-- etc.
```
The actual files live under `kong/plugins/karna/modules/` and `kong/plugins/karna/rules/`, but the rockspec maps short names (without `ka_` prefix in some cases — check the rockspec for the authoritative mapping).

## Audit Logging
- Logs are written as JSON files to `auditlog_path` (default `/usr/local/openresty/nginx/logs`).
- Format `v2` (default): one entry per request, all matched rules in `matches` array.
- Format `v1` (legacy): last-match wins, ModSecurity-compatible when `auditlog_modsec` is enabled.
- The upstream latency in v2 is read from header `x-karna-upstream-latency`
  if present, otherwise computed from `ngx.var.upstream_response_time`.
- Writing is done asynchronously via `ngx.timer.at`.
- **The audit-log directory must be writable by the Kong worker user.** The dev image chowns `/usr/local/openresty/nginx/logs` to `kong:kong` for this reason. On a custom deployment, ensure the configured `auditlog_path` matches.

## Always-on validation gates (not toggle-gated)
The access phase runs four request-validation methods *before* the rule
loops, and they fire regardless of `coreruleset_enabled` /
`local_rules_enabled`:

- `engine:method_allowed(plugin_conf)` — vs `request_methods_allowed`
- `engine:uri_path_check_violation(plugin_conf)` — special-char / invalid-char limits in path
- `engine:check_request_headers_allowed(plugin_conf)` — vs `request_headers_denied`
- `engine:check_request_content_type_charset(plugin_conf)` — vs `request_content_type_*`

Treat these as hard limits — they cannot be turned off short of removing
the plugin. To loosen them, raise the relevant numeric limits or
allow-lists (`limit_special_chars_in_path`, `request_methods_allowed`,
…). When debugging "why was this blocked with all toggles off?", these
are usually the answer.

## Optional integration points (for chained-plugin deployments)

Karna can opportunistically read state set by sibling plugins. These are
all guarded — when no sibling plugin sets them, Karna works fine in isolation.

- `kong.ctx.shared.response_from_cache` — short-circuits WAF when an upstream cache plugin served the response.
- `kong.ctx.shared.geoip_country_code|country_name|continent_code|continent_name` — enriches the inspection table for geo-based rules.
- Header `x-karna-upstream-latency` (ms) — overrides the nginx upstream timer in audit logs.

## Tests
- `tests/` — ad-hoc Lua scripts (run from repo root: `lua tests/<name>.lua`)
- `ka-unittest/` — unit test snippets
- `ka-regression-tests/` — regression suite (requires `busted` + a kong/ngx mock — see `kong_ngx_global.lua`)
- `ka-integration-tests/` — `hurl`-based end-to-end against a running Kong
- `ka-stress-test/` — Python load test
- `crs-regression-test/` — official OWASP CRS regression suite runner

CI is not yet wired up.

## Versioning
SemVer + LuaRocks revision (`MAJOR.MINOR.PATCH-REV`). **Don't forget**: the
`VERSION` constant in `handler.lua` must match the rockspec on every release
(rockspec carries the `-REV` suffix, the handler `VERSION` is SemVer pure).
