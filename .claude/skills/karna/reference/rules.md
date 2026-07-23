# Karna rule reference

A rule is a JSON object placed in the `rules_request` array — every custom rule
goes there regardless of phase, and the engine runs it in the phase named by its
`phase` field. There is no separate response array; the engine dispatches by
phase. A rule fires when **all** its conditions match, then runs its `action`.
Authoritative engine: `kong/plugins/karna/modules/ka_engine.lua`.

## Rule shape

```json
{
  "id": "1234",
  "phase": "access",
  "conditions": [
    { "op": "rx", "transform": ["urlDecodeUni"], "value": "['\"`]+",
      "variables": ["request.arg.value"], "multi_match": false }
  ],
  "action": { "fixed_response": { "status_code": 403, "body": "Forbidden\r\n" } },
  "log": true,
  "message": "Example rule",
  "tags": ["injection"],
  "rule_control": []
}
```

Fields: `id`, `phase`, `conditions[]`, `action`, `message`, `tags[]`, `log`, optional `rule_control[]`.
Condition fields: `variables[]`, `op`, `value`, `transform[]` (omit/`[]` for none), `negated` (bool), `multi_match` (bool).
Conditions are AND-ed (a chain). Later conditions can read `matched.value` and capture groups `group:0`, `group:1`, …

## Phases
Set a rule's `phase` to one of these. Custom rules run in `access` and
`header_filter` only.
- `access` — before upstream. Inspects method/path/query/headers/cookies/parsed body. Can block, sanitize, modify. Most rules.
- `header_filter` — after upstream responds. Sees the request plus `response.status` / `response.header.*` / `response.set_cookie.*` (resolvable in conditions, not just in `%{}` macros). Use this to react to the response — e.g. count a failed login by its status.
- `body_filter` — response body. Custom rules in this phase are **not currently evaluated** (the handler dispatch is commented out); the phase is used internally for MCP SSE reassembly.
- `mcp_event` — per reassembled SSE event (Karna-native, MCP only); can drop/replace/terminate/inject events.

## Evaluation order
Within a phase the engine runs, in this order: rule controls → CRS exclusion
plugins + `custom_secrules` pass-rules (ctl side effects) → **global rules**
(Redis pack, if published) → local rules (`rules_request`) → CRS. Within each
list rules run in order. Non-terminal side effects
(`set_variable`, `set_log_fields`, `redis_incr_key`) fire on **every** matching
rule. The first rule whose action is **terminal** (`fixed_response`,
`fix_matched_parts`, `rate_limit`) stops evaluation and wins. So a counter that
must always increment belongs on a non-terminal rule, and a "block if already
banned" check placed first short-circuits the rest.

## Variables (append `:<selector>` to target a named element)
- `request.arg.value` / `.name` — query + parsed body args (canonical "any arg"). Target one: `request.arg.value:<name>`.
- `request.query.value` / `.name` — query string only.
- `request.body.urlencode.value:<name>`, `request.body.json.value:<path>`, `request.body`.
- `request.header.value` / `.name` (`request.header.value:host`), `request.header_no_fp.value` (excludes FP-prone headers).
- `request.cookie.value` / `.name`.
- `request.raw_path`, `request.basename`, `request.method`.
- `request.file`, `request.body.multipart.filename`, `request.body.multipart.header.value`.
- `request.header.referer.{path,query,scheme,host}`.
- `response.status`, `response.header.value:<name>` / `.name:<name>`, `response.set_cookie.value` / `.name` (header_filter phase; resolvable in conditions).
- `matched.value`, `group:<n>` (chain refs).
- `tx:<name>` / `var:<name>` (CRS TX vars, e.g. `var:paranoia_level`).
- `redis.<key>` — inspect a Redis key (read-only). Everything after `redis.` is the key name (macros allowed: `%{remote_addr}`, `%{request.method|host|scheme|path}`, `%{request_headers.X}`). The **operator picks the command**: `isSet`→EXISTS (ban/existence check; `negated:true`→absent), `eq`/`rx`/`contains`/`beginsWith`→GET+compare, `gt`/`lt`/`ge`/`le`→GET+numeric, `redis_sismember`→SISMEMBER, `redis_hexists`→HEXISTS. Needs `redis_inspect_enabled`. (Legacy `redis.key:<macro>` GET form is dead — use `redis.<key>`.)
- `geoip.*` / `asn.*` (enrichment), `mcp.*` (when mcp_enabled).

## Operators (`op`)
`rx` (regex), `eq`, `ge`/`gt`/`lt`/`le` (numeric, non-numeric fails closed), `beginsWith`/`endsWith`, `contains`, `within` (token list), `isSet`, `pm`/`pmFromFile` (phrase match), `ipMatch` (CIDR list), `libinjection_sqli`/`libinjection_xss`, `validateUrlEncoding`, `validateUtf8Encoding`, `validateByteRange` (`"32-126,9,10,13"`), `unconditionalMatch`, `mcp_method_in`, `mcp_jsonrpc_valid`, `redis_sismember` (value ∈ Redis SET named by the `redis.<key>` var; negatable=not-a-member/allowlist), `redis_hexists` (Redis HASH named by `redis.<key>` has field=value; negatable). The two `redis_*` ops need `redis_inspect_enabled`.
Use `value: ""` for operators that take no argument (`isSet`, `libinjection_*`).
Not implemented (rules skipped with WARN at parse): `@ipMatchFromFile`, `@verifyCC`, `@verifySSN`, `@geoLookup`, `@inspectFile`.

## Negation
Canonical: `"negated": true` (separate boolean, not a `!` prefix). Legacy `"op": "!rx"` still accepted on input; prefer `negated`.
A negated condition fires when the positive fails AND the value is present. Exception: `isSet` + `negated:true` is how you spell "variable absent" and fires on a missing variable.

## Transformations (in `transform`, applied in order; no implicit transforms)
`lowercase`, `urlDecodeUni`(=`urlDecode`), `hexSequenceDecode`, `htmlEntityDecode`, `jsDecode`, `cssDecode`, `escapeSeqDecode`, `base64Decode`(=`base64decode`), `removeNulls`, `removeWhitespace`, `compressWhitespace`, `replaceComments`, `removeCommentsChar`, `normalisePath`(=`normalizePath`), `normalizePathWin`, `cmdLine`, `utf8toUnicode`, `length` (→ number), `sha1`, `hexEncode`.

## Actions (side-effect actions fire even in detection-only; terminal actions block only when engine_blocking_mode is on)
- `fixed_response`: `{ status_code, headers, body }` — standard block.
- `fix_matched_parts`: `{ remove_chars_pattern }` — strip chars from matched targets in place, forward upstream; logs `action:"sanitized"`. **Takes precedence over `fixed_response`.**
- `rate_limit`: `{ key (macro, default %{remote_addr}), limit, window_seconds, response{} }` — Redis fixed-window, 429 + auto Retry-After over limit. Counter increments even in detection-only.
- `redis_incr_key`: `{ key (macro), expire }` — increment a Redis key with TTL.
- `redis_set` / `redis_sadd` / `redis_del`: write cluster-wide state on a match (auto-ban primitive). Fire-and-forget (sync in `access`, timer-deferred later; never blocks). Keys/values/members are macro-resolved.
  - `redis_set`: `{ key, value (default "1"), expire }` → `SET key value [EX expire]`.
  - `redis_sadd`: `{ key, member, expire }` → `SADD key member` [+ `EXPIRE key expire`].
  - `redis_del`: `{ key }` → `DEL key` (manual unban/clear).
  - Close the auto-ban loop: `redis_set ban:%{remote_addr} EX 600` (write) + a rule with `isSet` on `redis.ban:%{remote_addr}` (read) blocks every node.
- `set_variable`: `{ name, value, type }` — `type` required: `shared` → `kong.ctx.shared`, `plugin` → `kong.ctx.plugin`. String values support `%{var}` macros. `value:false` is valid; only `nil` means "absent".
- `set_log_fields`: `[ { name, value } ]` — add fields to the audit log (value supports `%{var}`).
Macros for `key`/templates: `%{remote_addr}`, `%{request.method|host|scheme|path}`, plus any inspection-table var in `set_variable`/`set_log_fields`. Redis `redis.<key>` variables and `redis_set/sadd/del` keys/values also resolve `%{request_headers.X}`; the `redis_sismember`/`redis_hexists` needle (condition.value) resolves `%{remote_addr}`/`%{request.*}`/`%{request_headers.X}`.

## Rule controls (`rule_control[]` — modify this/other rules by id or tag)
- `remove_rule` `{rule_id}` (range ok: `"920100-920199"`), `remove_rules_by_tag` `{tag}`.
- `remove_variable_from_rule_conditions` `{rule_id, variable_name}`.
- `remove_variable_rx` `{name, rx}` — drop variables whose key matches a regex (libinjection header FPs).
- `remove_target_rule_by_pattern` `{rule_id, pattern}`, `remove_target_tag_by_pattern` `{tag, pattern}`.
- `change_rule_action` `{rule_id, action}`, `change_condition_tfunc` `{rule_id, condition_number, new_tfunc}` (1-based), `change_condition_value` `{rule_id, condition_number, new_value}`.
- `replace_condition` / `remove_condition` / `add_condition` `{rule_id, condition_number, ...}`.

## SecLang option
`custom_secrules` accepts raw `SecRule <vars> "<op>" "<actions>"` strings (only the canonical form; `SecRule*` derivatives skipped). Parsed at worker start into the global pool. `deny` and `block` both map to a 403 `fixed_response`; an explicit `status:NNN` is honoured.

## Global rules (one pack for every service, via Redis)
Karna is attached per-service; the global rules pack is how one rule set reaches
**all** services with no per-service config and no reload. Operators publish two
payloads (a JSON rule array — same format as `rules_request` — and/or a SecLang
text) to the Redis hash `karna:global_rules` with
`scripts/karna-rules.py --type global-rules --redis <url> --json f.json --seclang f.conf`
(also `--show` to inspect, `--pull` to recover the files, `--dry-run`). Workers
poll the version field (env `KARNA_GLOBAL_RULES_POLL`, default 30s) and hot-swap
the pack. Enable by setting `KARNA_REDIS_URL` on the Kong nodes; sign packs with
`KARNA_GLOBAL_RULES_HMAC_KEY` (same key on publisher and nodes — unsigned mode
works but warns loudly). Bad signature / Redis outage → last known good pack
stays; `DEL karna:global_rules` → pack cleared. Global rules run before local
rules; phases: `access`, `header_filter`, `mcp_event` (no `body_filter`). There
is no per-service opt-out — tag pack rules (e.g. `global-pack`) so per-service
`rule_action_overrides` or `ctl:*` exclusions can tame one rule where needed.
Blocking still follows each service's `engine_blocking_mode`.

See `recipes.md` for end-to-end examples; the public docs at `/docs/rules.html` carry fuller worked examples.
