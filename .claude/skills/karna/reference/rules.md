# Karna rule reference

A rule is a JSON object placed in `rules_request` (request phase) or
`rules_response` (response phase). It fires when **all** conditions match, then runs
its `action`. Authoritative engine: `kong/plugins/karna/modules/ka_engine.lua`.

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
- `access` — before upstream. Inspects method/path/query/headers/cookies/parsed body. Can block, sanitize, modify. Most rules.
- `header_filter` — after upstream responds. Request + response status/headers.
- `body_filter` — response body streaming (internal MCP SSE reassembly).
- `mcp_event` — per reassembled SSE event (Karna-native); can drop/replace/terminate/inject events.

## Variables (append `:<selector>` to target a named element)
- `request.arg.value` / `.name` — query + parsed body args (canonical "any arg"). Target one: `request.arg.value:<name>`.
- `request.query.value` / `.name` — query string only.
- `request.body.urlencode.value:<name>`, `request.body.json.value:<path>`, `request.body`.
- `request.header.value` / `.name` (`request.header.value:host`), `request.header_no_fp.value` (excludes FP-prone headers).
- `request.cookie.value` / `.name`.
- `request.raw_path`, `request.basename`, `request.method`.
- `request.file`, `request.body.multipart.filename`, `request.body.multipart.header.value`.
- `request.header.referer.{path,query,scheme,host}`.
- `response.set_cookie.value` / `.name`, `response.header.name:<name>` (response phases).
- `matched.value`, `group:<n>` (chain refs).
- `tx:<name>` / `var:<name>` (CRS TX vars, e.g. `var:paranoia_level`).
- `redis.key:<macro>` (Redis value), `geoip.*` / `asn.*` (enrichment), `mcp.*` (when mcp_enabled).

## Operators (`op`)
`rx` (regex), `eq`, `ge`/`gt`/`lt`/`le` (numeric, non-numeric fails closed), `beginsWith`/`endsWith`, `contains`, `within` (token list), `isSet`, `pm`/`pmFromFile` (phrase match), `ipMatch` (CIDR list), `libinjection_sqli`/`libinjection_xss`, `validateUrlEncoding`, `validateUtf8Encoding`, `validateByteRange` (`"32-126,9,10,13"`), `unconditionalMatch`, `mcp_method_in`, `mcp_jsonrpc_valid`.
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
- `set_variable`: `{ name, value, type }` — `type` required: `shared` → `kong.ctx.shared`, `plugin` → `kong.ctx.plugin`. String values support `%{var}` macros. `value:false` is valid; only `nil` means "absent".
- `set_log_fields`: `[ { name, value } ]` — add fields to the audit log (value supports `%{var}`).
Macros for `key`/templates: `%{remote_addr}`, `%{request.method|host|scheme|path}`, plus any inspection-table var in `set_variable`/`set_log_fields`.

## Rule controls (`rule_control[]` — modify this/other rules by id or tag)
- `remove_rule` `{rule_id}` (range ok: `"920100-920199"`), `remove_rules_by_tag` `{tag}`.
- `remove_variable_from_rule_conditions` `{rule_id, variable_name}`.
- `remove_variable_rx` `{name, rx}` — drop variables whose key matches a regex (libinjection header FPs).
- `remove_target_rule_by_pattern` `{rule_id, pattern}`, `remove_target_tag_by_pattern` `{tag, pattern}`.
- `change_rule_action` `{rule_id, action}`, `change_condition_tfunc` `{rule_id, condition_number, new_tfunc}` (1-based), `change_condition_value` `{rule_id, condition_number, new_value}`.
- `replace_condition` / `remove_condition` / `add_condition` `{rule_id, condition_number, ...}`.

## SecLang option
`custom_secrules` accepts raw `SecRule <vars> "<op>" "<actions>"` strings (only the canonical form; `SecRule*` derivatives skipped). Parsed at worker start into the global pool.

See `recipes.md` for end-to-end examples; the public docs at `/docs/rules.html` carry fuller worked examples.
