# Changelog

All notable changes to Karna are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Reject malformed multipart parts with no body section. A part whose boundary
  is glued directly onto the headers terminator (`...name="x"\r\n\r\n--boundary`
  — two CRLFs) instead of the well-formed empty-field form
  (`...name="x"\r\n\r\n\r\n--boundary` — three CRLFs) is malformed: RFC 2046
  delimits a part body with `CRLF--boundary`, so even an empty field carries
  its body's trailing CRLF. A backend that honours that delimiter reads the
  following boundary line as this part's body and swallows the next part, while
  a line-based WAF sees an empty part — the multipart empty-part desync from
  terjanq's WAF-bypass write-up (#3), which let an attack hidden in a file part
  reach the backend as a regular field value. Such a body is now rejected by
  the always-on body-parser gate (403). Legitimate empty fields (curl and
  browsers emit the full three-CRLF form) are unaffected. Verified with CRS PL1
  regression at 2757/2757.

## [1.1.3] - 2026-06-10

### Security

- Inspect top-level JSON scalar request bodies. A body that decodes to a bare
  JSON scalar — a string, number, or boolean (e.g. `"' OR '1'='1"`) — has no
  object or array to flatten, so the value never reached ARGS and slipped past
  the rule engine, while a lenient backend that re-parses the body as form data
  still acted on it (the JSON content-type-confusion bypass from terjanq's
  WAF-bypass write-up). The body parsed cleanly, so the always-on body-parser
  gate didn't catch it either — the JSON twin of the XML empty-document gap
  closed in 1.1.2. The scalar is now surfaced as a single argument value and
  inspected like any other parameter. Benign scalar bodies (`"hello"`, `123`)
  are unaffected. Verified with CRS PL1 regression at 2757/2757.

## [1.1.2] - 2026-06-10

### Security

- Fixed a body-parser content-type desync bypass. `request_body_parser_type`
  selected the parser with a case-insensitive *substring* match over the whole
  `Content-Type` header, using sequential `if` blocks where the last match won.
  A parser keyword smuggled into a parameter — e.g.
  `application/json;charset=myxml` — matched "json" and then "xml" (inside
  "myxml"), so Karna XML-parsed a JSON body while a backend read the base type
  `application/json` and parsed it as JSON. The parser desync left the
  arguments un-flattened, so a body attack (SQLi/XSS/…) skipped the rule
  engine. Combined with the XML empty-parse gap fixed below, the misclassified
  body reached the backend uninspected — a working bypass at every paranoia
  level. The selector fix also stops a keyword inside a parameter from
  misrouting a legitimate body, and closes a related desync via a parser that
  never errors (urlencoded). Classification now keys off the base
  media type only (the token before the first `;`/space), mirroring
  `check_request_content_type_enforce`, with `elseif` ordering instead of
  last-match-wins. Structured subtype suffixes (`+json`, `+xml`) are still
  honoured. Reported by Davide Virruso (z3er01 @ zeronvll).
- Deny XML-declared bodies that contain no XML elements. The SAX parser
  (slaxml) accepts a tag-less payload — a JSON or plain-text body with no
  `<...>` element — as a "successful" parse of an empty document: zero
  elements, no error. The body-parser gate keys off a parse *error*, so such a
  body slipped through with an empty argument set and was never inspected,
  while a lenient backend (e.g. one that force-parses the body as JSON
  regardless of `Content-Type`) still acted on it. A request with a valid
  `Content-Type: application/xml` / `text/xml` and a JSON SQLi body was a full
  bypass even after the content-type classification fix above. A non-whitespace
  body declared as XML that yields no element is now treated as a parse failure
  and blocked by the always-on body-parser gate. Genuine XML (including
  attribute-only and self-closing elements) and empty/whitespace bodies are
  unaffected. Verified with CRS PL1 regression at 2757/2757. Same report.

### Fixed

- Wired the `@validateUrlEncoding` and `@validateUtf8Encoding` operators into
  the SecLang parser. The engine already implemented both, but the parser's
  operator map was missing them, so any rule using them (CRS 920220 / 920250,
  in the default-off 920 protocol-enforcement family) loaded with a nil
  operator and silently never matched. No effect on the default configuration;
  enabling the 920 family now actually enforces these checks. Found during a
  white-box bypass audit.

## [1.1.1] - 2026-06-09

### Security

- Fixed a path-confusion inspection bypass (CVE-2024-1019 class). A payload
  hidden in the request path — after an encoded `?` (`%3f`), e.g.
  `/1%3f' OR '1'='1`, or inside a `;key=value` path parameter (matrix params,
  jsessionid-style) — never entered the query string, so the ARGS-targeted
  rules (libinjection SQLi / XSS, …) never saw it, even though a backend that
  decodes `%3f` or parses path parameters would. That hidden path material is
  now surfaced into ARGS and inspected, the same way a real query argument is.
  Additive — nothing is removed from existing path inspection, and benign
  paths (matrix params, `jsessionid`, encoded filenames) are unaffected. Found
  while reviewing public path-confusion bypass research; verified locally with
  CRS PL1 regression at 2757/2757.

## [1.1.0] - 2026-06-09

Continues the request-body inspection bypass hunt started in 1.0.1, guided by
public WAF-bypass research on parser discrepancies. Closes the remaining
content-type and structured-body evasion classes.

### Security

- Block body-bearing requests Karna cannot inspect. A request body with no
  `Content-Type`, or one that maps to the raw "text" fallback (`text/plain`,
  `application/octet-stream`, `image/*`, `application/foo`, …), was never
  flattened into arguments, so a structured attack smuggled inside it skipped
  the rule engine entirely. A body's base `Content-Type` must now be present and
  in `request_content_type_allowed`, else the request is blocked. "Deny what you
  can't inspect."
- Block structured bodies that fail to parse. A body declared as JSON but
  carrying a lone NUL byte, trailing junk after the object, a duplicate key, or
  a truncated object — and a body declared as XML with a raw `<` inside an
  attribute value — could not be parsed, so it slipped past every rule with an
  empty argument set. These parser-discrepancy evasions (different parser on the
  WAF vs the backend) are now rejected by the always-on body-parser gate, the
  same way malformed multipart already was.
- Inspect XML attribute values. Attack rules targeting `XML:/*` only scanned
  element text, so SQLi / XSS hidden in an XML *attribute*
  (`<x q="1' OR '1'='1"/>`) was never inspected. `XML:/*` now scans element
  values and attribute values (names are still excluded — folding names in is
  the 944120-class false-positive vector).

### Added

- `request_content_type_enforce` (boolean, default `true`) — the toggle for the
  uninspectable-body gate above. Set it `false` to restore the permissive
  behaviour for deployments that legitimately accept arbitrary body content
  types.

### Changed

- Default behaviour change: requests carrying a body with a missing or
  non-allow-listed `Content-Type` are now blocked by default. Review
  `request_content_type_allowed` (or set `request_content_type_enforce=false`)
  if your services accept `text/plain`, `application/octet-stream`, or other
  unparsed body types.

## [1.0.1] - 2026-06-09

### Security

- Fixed a request-body inspection bypass with `Transfer-Encoding: chunked`. A
  chunked request carries no `Content-Length`, and the engine keyed body
  inspection (and the "skip body rules" fast path) off `Content-Length`, so an
  attack payload sent in a chunked body skipped inspection entirely and reached
  the upstream. Body presence is now derived from `Content-Length` OR
  `Transfer-Encoding`, and the buffered-to-disk path no longer requires
  `Content-Length`. Reported externally; reproduced and fixed.
- Fixed two more request-body inspection bypasses of the same shape, found while
  auditing the chunked fix. The body-parser dispatch matched the `Content-Type`
  header case-sensitively, so `application/JSON` or
  `APPLICATION/X-WWW-FORM-URLENCODED` fell through to the raw "text" path and
  the structured arguments were never inspected; the header is now lowercased
  before matching, per its case-insensitive definition. Separately, a JSON body
  sent with `text/plain` or with no `Content-Type` at all also fell through to
  the raw path, so a lax upstream that parses it as JSON anyway would process an
  attack that the WAF had skipped; bodies without a structured content-type are
  now content-sniffed and, when they are well-formed JSON, inspected as JSON
  (matched arguments fold into ARGS exactly like the declared-JSON path).
- Hardened CI and the build supply chain: pinned every GitHub Action, the Docker
  base image, libinjection, and the CRS tarball by commit SHA / digest / sha256;
  added least-privilege `permissions: contents: read`, per-job timeouts, and a
  concurrency guard to the Actions workflow; pinned and hashed the Python test
  dependency. (Pair with the repo setting "Require approval for all external
  contributors".)

### Changed

- Updated the base image and dev stack: Kong 3.9.2, Postgres 17, lua-zlib 1.4.

## [1.0.0] - 2026-06-08

First public release. Karna is a self-contained Web Application Firewall that
runs as a native Kong Gateway plugin (priority 8300), compatible with the OWASP
Core Rule Set. It needs no other plugin to work.

### Added

- OWASP CRS 4.x loader at worker start (tracked against 4.26.0), with SecLang
  operators mapped to engine-native names.
- SQLi / XSS detection via libinjection (FFI).
- Rules in SecLang or JSON, per service, changeable at runtime through Kong's
  Admin API with no reload.
- `fix_matched_parts` — sanitize matched input in place instead of blocking.
- Config-level action and response overrides (`rule_action_overrides`,
  `rule_response_overrides`) and a rule-control layer to patch CRS rules without
  forking the pack.
- Native Redis rate limiting (`rate_limit`) and counters (`redis_incr_key`).
- Redis inspection: `redis.<key>` variables and the `redis_sismember` /
  `redis_hexists` operators (gated by `redis_inspect_enabled`), plus the
  `redis_set` / `redis_sadd` / `redis_del` write actions for distributed state
  and auto-ban.
- MCP (Model Context Protocol) request inspection and SSE response reassembly,
  with per-event rules.
- Always-on request-validation gates: method, path characters, denied headers,
  content-type / charset.
- CRS exclusion plugins loaded from disk (WordPress, Drupal, …) and inline
  `custom_secrules`.
- Per-service CRS category toggles (`coreruleset_rulesets`).
- JSON audit log v2 (one entry per request, all matches in `matches[]`) with
  custom fields via `set_log_fields`; a ModSecurity-compatible v1 is also
  available.
- Request enrichment: `geoip.*` / `asn.*` rule variables and audit-log blocks
  populated by sibling plugins.
- `set_variable` action to pass state to sibling Kong plugins via
  `kong.ctx.shared`.
- Tooling: `scripts/install.sh` (one-command install into an existing Kong),
  `scripts/karna-rules` (push rules and overrides via the Admin API), and a
  self-contained Docker dev/prod stack.
- Self-identification endpoint `GET /.well-known/karna` returning
  `{engine, version, commit, commit_short, built_at}`; the same version + commit
  are recorded in the `engine` block of every audit-log v2 entry. The build
  stamps `version.lua` (Docker build arg / `scripts/install.sh`).

### Performance

- RE2::Set gate for the `@rx` operator — linear-time, ReDoS-safe matching, with
  body-namespace coverage and a literal prefilter.
- Aho-Corasick (`libka_ac`) backing for `@pm` / `@pmFromFile`.
- Hot-path work reduced: per-request caches, transform-chain caching, a
  precompiled per-rule resolver, and keeping file-upload bodies out of ARGS
  scope. The native scanners ship in the image and fall back to pure Lua if
  absent.

### Notes

- `protocol_enforcement` (CRS 920) ships disabled by default: nginx and Karna's
  always-on gates already enforce request well-formedness.
- `ignore_from_local_ips` defaults to `false`: loopback / RFC1918 source IPs are
  inspected by default (set it to `true` to bypass trusted internal ranges).
- The PL1 OWASP CRS regression suite passes at 100%.

[Unreleased]: https://github.com/sicuranext/karna/compare/v1.1.3...HEAD
[1.1.3]: https://github.com/sicuranext/karna/compare/v1.1.2...v1.1.3
[1.1.2]: https://github.com/sicuranext/karna/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/sicuranext/karna/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/sicuranext/karna/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/sicuranext/karna/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/sicuranext/karna/releases/tag/v1.0.0
