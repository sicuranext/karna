# Changelog

All notable changes to Karna are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Fixed a request-body inspection bypass with `Transfer-Encoding: chunked`. A
  chunked request carries no `Content-Length`, and the engine keyed body
  inspection (and the "skip body rules" fast path) off `Content-Length`, so an
  attack payload sent in a chunked body skipped inspection entirely and reached
  the upstream. Body presence is now derived from `Content-Length` OR
  `Transfer-Encoding`, and the buffered-to-disk path no longer requires
  `Content-Length`. Reported externally; reproduced and fixed.
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

[Unreleased]: https://github.com/sicuranext/karna/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/sicuranext/karna/releases/tag/v1.0.0
