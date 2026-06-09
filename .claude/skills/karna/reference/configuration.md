# Karna configuration reference

Source of truth: `kong/plugins/karna/schema.lua`. All options are per-service, set
under the plugin `config` block. Defaults shown in `(parens)`.

## Engine & blocking
- `engine_blocking_mode` (bool, `false`) — block on match (default 403) vs detection-only. Start `false`.
- `coreruleset_enabled` (bool, `true`) — load/evaluate the OWASP CRS pack. The in-repo CRS-fix controls always apply regardless.
- `local_rules_enabled` (bool, `true`) — evaluate `rules_request` / `rules_response`.
- `set_karna_headers` (bool, `false`) — add diagnostic response headers.

## CRS category toggles (under `coreruleset_rulesets`, gated by `coreruleset_enabled`)
Each bool, default `true` except where noted. Disabling skips that category in the eval loop.
`method_enforcement` (911), `scanner_detection` (913), `protocol_enforcement` (920, **default false** — nginx already enforces protocol well-formedness), `protocol_attack` (921), `multipart_attack` (922), `lfi` (930), `rfi` (931), `rce` (932), `php` (933), `generic` (934), `xss` (941), `sqli` (942), `session_fixation` (943), `java` (944).
Not toggleable: anomaly scoring (949/959/980), response rules (95x), init (901), common exceptions (905/999).

## Engine optimizations (all bool, default `true`, detection-neutral, graceful fallback)
- `engine_re2_match` — run `@rx` via RE2 (linear-time, ReDoS-safe). Needs `libka_re2.so`.
- `engine_re2_scan` — RE2::Set prefilter gate for `@rx` (~2x benign throughput). Needs `libka_re2.so`.
- `engine_ac_pm` — C Aho-Corasick for `@pm`/`@pmFromFile`. Needs `libka_ac.so`.
- `engine_fast_path` — skip per-rule ARGS deep-copy when no rule_control mutation pending.
(Three further opts are unconditional/no-toggle, all CRS-empty-diff proven.)

## Always-on validation gates & limits (gates fire before the rule loop, regardless of blocking mode)
- `request_methods_allowed` (array; default GET/HEAD/PUT/POST/DELETE/OPTIONS/PATCH/PROPFIND) — **gate**.
- `check_special_chars_in_path` (bool, `true`) + `limit_special_chars_in_path` (num, `3`) — **gate**.
- `check_invalid_chars_in_path` (bool, `false`) + `limit_invalid_chars_in_path` (num, `1`) — **gate**.
- `request_headers_denied` (array; default content-encoding/proxy/lock-token/content-range/if) — **gate**.
- `request_content_type_allowed` (array) / `request_content_type_charset_allowed` (array; utf-8/iso-8859-1/iso-8859-15/windows-1252) — **gate**.
- `request_content_type_enforce` (bool, `true`) — **gate**. A body-bearing request must declare a `Content-Type` present in `request_content_type_allowed`; bodies with no/unknown CT (text/plain, octet-stream, image/*, …) can't be parsed into args, so they're blocked by default ("deny what you can't inspect"). Set `false` to accept arbitrary body content types.
- `limit_arg_num` (num, `255`) — **gate** (DoS protection against rules×args blow-up).
- `limit_arg_name_length` (num, `100`), `limit_arg_value_length` (num, `400`), `total_arg_value_length` (num, `64000`).
- `restricted_extensions` (array) — blocked path extensions, aligned with CRS `tx.restricted_extensions`.
- `ignore_from_local_ips` (bool, `false`) — when `true`, skip WAF for loopback/RFC1918 source IPs. Default `false` = inspect everything. **If set `true`, local-sourced attacks (incl. from an LB's private egress IP) no-op.**

To loosen a gate, raise its value / extend its allow-list. They cannot be turned off short of removing the plugin.

## CRS-setup knobs
- `paranoia_level` (num, `1`) — CRS paranoia 1–4.
- `validate_utf8_encoding` (bool, `true`) — maps to `TX:CRS_VALIDATE_UTF8_ENCODING`.

## Body parsing
- `try_bas64decode_if_possible` (bool, `false`) — base64-decode values during parsing.
- `inspection_table_convert` (array) — advanced; extra namespaces to flatten. Leave unset unless needed.

## MCP (off by default; identical to normal traffic until enabled)
`mcp_enabled` (`false`), `mcp_routes` (`[]`), `mcp_detection_heuristic` (`false`), `mcp_protocol_versions_allowed` (`[2025-11-25,2025-06-18,2025-03-26]`), `mcp_block_legacy_sse_transport` (`false`), `mcp_origin_check_enabled` (`true`), `mcp_origins_allowed` (`[]`), `mcp_max_event_size_bytes` (`1048576`), `mcp_max_stream_buffer_bytes` (`8388608`), `mcp_redact_session_id_in_audit` (`true`), `mcp_redact_authorization_in_audit` (`true`).

## CRS exclusion plugins
- `crs_plugins_path` (str, `/opt/coreruleset-plugins/`) — cloned CRS plugin repos.
- `crs_plugins_enabled` (array, `[]`) — plugin dir names to load (e.g. `wordpress-rule-exclusions-plugin`).

## Custom rules
- `rules_request` (array) — per-service request rules (JSON strings). See `rules.md`.
- `rules_response` (array) — per-service response rules.
- `custom_secrules` (array, `[]`) — inline SecLang `SecRule` strings.

## Action / response overrides (change existing rules without editing the pack)
- `rule_action_overrides` (array, `[]`) — `{selector, action}` where action.type is `fix` (sanitize, with `remove_chars_pattern`), `passthrough` (drop terminal), or `block`.
- `rule_response_overrides` (array, `[]`) — `{selector, response}` with `status_code`/`body` (supports `%{var}`)/`headers`.
- Selector grammar: `ids`, `id_ranges` (`"941000-941999"`), `tags`, `except_ids`, `except_tags`, `any:true`. First match wins; cached pack never mutated.

## Audit logging
- `auditlog_enabled` (bool, `true`), `auditlog_path` (str, `/usr/local/openresty/nginx/logs`, must be kong:kong-writable), `auditlog_format` (`v2`|`v1`, default `v2`), `auditlog_only_on_match` (bool, `false`), `auditlog_modsec` (bool, `false`), `auditlog_error_log_on_match` (bool, `false`).

## Redis (optional; backs rate_limit, redis_incr_key, redis.<key> inspection, redis_sismember/redis_hexists ops, redis_set/sadd/del write actions)
- `redis_host` (str, `localhost`), `redis_port` (num, `6379`), `redis_password` (str, optional).
- `redis_database` (num, `0`) — DB index; `SELECT` issued only when > 0.
- `redis_inspect_enabled` (bool, `false`) — master switch for `redis.<key>` reads + `redis_sismember`/`redis_hexists`. Off by default (no rule opens a Redis connection unless you ask). Does NOT gate the write actions or rate_limit/redis_incr_key.
- `redis_timeout_ms` (num, `50`) — connect/send/read timeout for inspection reads (kept short so a slow Redis can't stall the request path).
- `redis_keepalive_pool_size` (num, `64`), `redis_keepalive_idle_ms` (num, `60000`) — inspection client connection pool.
- `redis_on_error` (str, `skip`; one_of skip/fail_open/fail_closed) — inspection read when Redis is down: `skip`/`fail_open` = no match (traffic flows), `fail_closed` = match (deny on unreadable shared state). Default `skip` keeps a Redis outage from blocking traffic.
- Read-only boundary: the inspection client enforces a deny-by-default command whitelist (GET/EXISTS/SISMEMBER/HEXISTS/TTL/… only). A `redis.<key>` variable can never run a write/admin/scripting/scan command; mutations go only through the write actions.

## Debug
- `private_debug` (bool, `false`) — verbose internal output, off in prod.

## Identification (always on, no config flag)
- `GET /.well-known/karna` → JSON `{engine, version, commit, commit_short, built_at}`. Confirms Karna is in the request path and reports the build. Same `version`/`commit` in the audit-log v2 `engine` block. Commit is stamped at build (Docker build arg `KARNA_COMMIT` / `scripts/install.sh`); an unstamped `luarocks make` reports `commit:"unknown"`. Reserved path — never reaches the upstream. Transparent watermark, passive (no phone-home).
