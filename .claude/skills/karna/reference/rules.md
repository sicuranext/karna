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
plugins + `custom_secrules` pass-rules (ctl side effects) → **global rules
exclusions** (disk pack, then Redis pack) → **global rules detection** (disk,
then Redis) → local rules (`rules_request`) → CRS. Within each list rules run in
order. Non-terminal side effects
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
- `request.raw_path` (verbatim path — percent-encoding intact, dot segments intact; match this for traversal/encoding evasion), `request.path` (nginx-normalized: dot segments resolved, percent-decoded except `%2F` — the view the upstream routes on), `request.path_with_query` (verbatim + query string), `request.basename`, `request.method`.
- `request.file`, `request.body.multipart.filename`, `request.body.multipart.header.value`.
- `request.header.referer.{path,query,scheme,host}`.
- `response.status`, `response.header.value:<name>` / `.name:<name>`, `response.set_cookie.value` / `.name` (header_filter phase; resolvable in conditions).
- `request.remote_addr` — client IP as seen on the transport (ModSec `REMOTE_ADDR`; same value as the `%{remote_addr}` macro). `request.forwarded_addr` — Kong's forwarded client (`X-Forwarded-For` walked back through Kong's `trusted_ips`, falling back to the peer when the header is absent or the peer is untrusted). Behind a CDN/LB use the second. Pair either with `ipMatch`.
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
- `log_only`: `true` — record this **non-terminal** match in the audit log as a real match (ModSec `pass,log`). Nothing blocked, nothing rewritten. Lands in `matches[]` (v2) / `messages[]` (v1) with id, message, tags and matched value, labelled `action: "log"`; works in `access` and `header_filter`. Being a real match it **satisfies `auditlog_only_on_match`** — without it a non-terminal rule writes nothing under that setting. Several can fire per request and all are kept (the loop doesn't stop). Opt-in on purpose: collecting every non-terminal match would flood the log with CRS `pass` helper rules, which can't be filtered by `log` (every CRS rule has `log = true`). `log_only` = collected, `log` = written, so `log: false` still suppresses it. `rule_action_overrides` do not reach a `log_only` rule.
Macros for `key`/templates: `%{remote_addr}`, `%{request.method|host|scheme|path}`, plus any inspection-table var in `set_variable`/`set_log_fields`. Redis `redis.<key>` variables and `redis_set/sadd/del` keys/values also resolve `%{request_headers.X}`; the `redis_sismember`/`redis_hexists` needle (condition.value) resolves `%{remote_addr}`/`%{request.*}`/`%{request_headers.X}`.

## Rule controls (`rule_control[]` — modify this/other rules by id or tag)
Per-request (a matching rule applies these to every rule evaluated after it — this is the `ctl:*` surface, and what a global-pack/local exclusion rule uses):
- `remove_rule` `{rule_id}` (range ok: `"920100-920199"`) ← `ctl:ruleRemoveById`.
- `remove_rules_by_tag` `{tag}` ← `ctl:ruleRemoveByTag`. Drops every rule carrying the tag.
- `remove_target_from_rule_by_id` `{rule_id, target}` ← `ctl:ruleRemoveTargetById`.
- `remove_target_rule_by_tag` `{tag, name}` ← `ctl:ruleRemoveTargetByTag`. Works on any tag. `tag: "OWASP_CRS"` is special-cased to mean **all rules** (custom ones included), not just CRS-tagged ones.
- `engine_off: true` ← `ctl:ruleEngine=Off`. Skips all remaining rule evaluation.
- `detection_only: true` ← `ctl:ruleEngine=DetectionOnly`. Rules still match, log, and run side effects; every terminal action is suppressed (`fixed_response`, the `rate_limit` 429, and `fix_matched_parts` sanitising). Audit log reports `engine.mode: "detection"` and `action: "detect"`.
- `body_access_off: true` ← `ctl:requestBodyAccess=Off`. The request body stops being inspected: `request.body`, the parsed body namespaces (json/xml/urlencode/multipart/files) and the body half of `request.arg.value` all resolve empty; query args, path, headers and cookies are unaffected. `request.body.processor` stays set (it comes from Content-Type).

**The always-on validation gates run before any rule control exists**, so none of these can switch off the method / path / header / content-type / body-parser / arg-count checks. Use the schema knobs for that.

Load-time (applied once at worker start, used by `coreruleset_fix.lua`):
- `remove_variable_from_rule_conditions` `{rule_id, variable_name}`.
- `remove_variable_rx` `{name, rx}` — drop variables whose key matches a regex (libinjection header FPs).
- `remove_target_rule_by_pattern` `{rule_id, pattern}`, `remove_target_tag_by_pattern` `{tag, pattern}`.
- `change_rule_action` `{rule_id, action}`, `change_condition_tfunc` `{rule_id, condition_number, new_tfunc}` (1-based), `change_condition_value` `{rule_id, condition_number, new_value}`.
- `replace_condition` / `remove_condition` / `add_condition` `{rule_id, condition_number, ...}`.

## SecLang option
`custom_secrules` accepts raw `SecRule <vars> "<op>" "<actions>"` strings (only the canonical form; `SecRule*` derivatives skipped). Parsed at worker start into the global pool. `deny` and `block` both map to a 403 `fixed_response`; an explicit `status:NNN` is honoured.

## Global rules (one pack for every service)
Karna is attached per-service; the global rules pack is how one rule set reaches
**all** services with no per-service config. Two independent sources, either or
both:

**Disk** — `KARNA_GLOBAL_RULES_PATH` points at a `.json` file or at a directory
whose `*.json` files load in filename order (prefix them `00-`, `10-` to control
it). Each file is a bare JSON array of rules in the Karna rule format, the same
array `rules_request` and the Redis `json` payload carry; no SecLang here. Read
synchronously once per worker at `init_worker`, so it is live before the first
request and there is no watcher: edits need `kong reload` or a restart. Not
signed — on disk the filesystem is the trust anchor. Each worker logs one
`notice` summary with the path, counts and a `sha256:` fingerprint of the bytes
(use it to check a fleet runs the same pack).

**Redis** — publish a JSON array and/or a SecLang text to the hash
`karna:global_rules` with
`scripts/karna-rules.py --type global-rules --redis <url> --json f.json --seclang f.conf`
(also `--show` to inspect, `--pull` to recover the files, `--dry-run`). Workers
poll the version field (env `KARNA_GLOBAL_RULES_POLL`, default 30s) and hot-swap
the pack. Enable with `KARNA_REDIS_URL`; sign packs with
`KARNA_GLOBAL_RULES_HMAC_KEY` (same key on publisher and nodes — unsigned mode
works but warns loudly). Bad signature / Redis outage → last known good pack
stays; `DEL karna:global_rules` → pack cleared.

**Both configured**: disk is evaluated before Redis, and duplicate rule ids are
first-wins, so Redis can add rules but cannot replace a rule deployed on disk
with one carrying the same id (the discarded copy is logged, naming both sides).
Same rule between two files of a directory: earlier filename wins.

**Blocking rules and exclusions in one pack**: order in the file does not
matter. At load each pack is split — rules with `rule_control` and no `action`
go to a *controls* list evaluated first on the multi-match path (so every
matching exclusion applies its `ctl:*`, in time to affect global detection
rules, local rules and the CRS); everything else goes to *detection* on the
standard first-terminal-wins path with the full action dispatch. A rule with
`rule_control` **plus** a real action stays in detection so it keeps that
dispatch.

Phases: `access`, `header_filter`, `mcp_event` (no `body_filter`).
`@pmFromFile` is not supported on this channel (rule dropped with a warning —
a pack ships no data files). Anything the engine could not evaluate (missing
`id`/`phase`/`conditions`, unsupported op, unevaluated phase) is dropped with
the id and reason; a file that does not decode is skipped and the others still
load. Global rules run before local rules. There is no per-service opt-out —
tag pack rules (e.g. `global-pack`) so per-service `rule_action_overrides` or
`ctl:*` exclusions can tame one rule where needed. Blocking still follows each
service's `engine_blocking_mode`.

See `recipes.md` for end-to-end examples; the public docs at `/docs/rules.html` carry fuller worked examples.
