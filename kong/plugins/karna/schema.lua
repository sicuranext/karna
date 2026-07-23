local typedefs = require "kong.db.schema.typedefs"

local plugin_name = ({...})[1]:match("^kong%.plugins%.([^%.]+)")

local schema = {
  name = plugin_name,
  fields = {
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          { set_karna_headers = { type = "boolean", default = false } },
          { engine_blocking_mode = { type = "boolean", default = false } },
          { coreruleset_enabled = { type = "boolean", default = true } },
          -- Per-service CRS ruleset-type switches. The full CRS is loaded once
          -- (init_worker, shared cache); these toggles decide which attack
          -- categories are EVALUATED for THIS service — a disabled category's
          -- rules are skipped in the eval loop (no per-request cost). Each
          -- defaults true; set false to silence a whole category for a service.
          -- Only the request-side attack categories are exposed — anomaly
          -- scoring (949/959/980), response rules (95x), init (901) and the
          -- common-exception files (905/999, which handle FP exclusions other
          -- rules depend on) are NOT toggleable. Gated by coreruleset_enabled.
          { coreruleset_rulesets = {
              type = "record",
              fields = {
                { method_enforcement = { type = "boolean", default = true } }, -- 911
                { scanner_detection  = { type = "boolean", default = true } }, -- 913
                -- 920 default OFF: HTTP protocol enforcement (method/version/
                -- header/encoding well-formedness) is already handled by
                -- nginx/OpenResty before the request reaches the rule engine,
                -- so the 920 pack is largely redundant in a Kong deployment.
                { protocol_enforcement = { type = "boolean", default = false } }, -- 920

                { protocol_attack    = { type = "boolean", default = true } }, -- 921
                { multipart_attack   = { type = "boolean", default = true } }, -- 922
                { lfi                = { type = "boolean", default = true } }, -- 930
                { rfi                = { type = "boolean", default = true } }, -- 931
                { rce                = { type = "boolean", default = true } }, -- 932
                { php                = { type = "boolean", default = true } }, -- 933
                { generic            = { type = "boolean", default = true } }, -- 934
                { xss                = { type = "boolean", default = true } }, -- 941
                { sqli               = { type = "boolean", default = true } }, -- 942
                { session_fixation   = { type = "boolean", default = true } }, -- 943
                { java               = { type = "boolean", default = true } }, -- 944
              },
          } },
          -- engine_fast_path: skip the per-rule ARGS deep-copy when no
          -- rule_control mutation is pending. Sound, +5-7%. Default ON.
          { engine_fast_path = { type = "boolean", default = true } },
          -- engine_re2_scan: gate per-rule @rx evaluation with a single
          -- RE2::Set scan per request value — rules whose @rx matched nothing
          -- are skipped; matched ones still run the full Lua path
          -- (captures/chain/setvar stay in Lua). ~2x benign throughput, sound
          -- (CRS regression empty-diff). Default ON; falls back to the pure-Lua
          -- @rx path when libka_re2.so is missing or a pattern is RE2-rejected.
          { engine_re2_scan = { type = "boolean", default = true } },
          -- engine_ac_pm: replace the Lua @pm / @pmFromFile keyword loops with
          -- a C Aho-Corasick (libka_ac.so) one-pass match (~16% of benign CPU
          -- was looping ~17 keyword files/157KB per value). +18% on top of RE2,
          -- sound. Default ON; falls back to the Lua loop when libka_ac.so is
          -- missing.
          { engine_ac_pm = { type = "boolean", default = true } },
          -- engine_re2_match: run the @rx operator's actual match via RE2
          -- (linear-time, ReDoS-safe BY CONSTRUCTION) instead of ngx.re/PCRE —
          -- removes the catastrophic-backtracking failure mode on attacker-
          -- controlled input (the cap that PCRE WAFs rely on aborts an
          -- *incomplete* match; RE2 needs no cap and matches fully). Covers CRS,
          -- custom_secrules and rules_request: per-pattern RE2 handles are
          -- precompiled at init (condition._re2_re); patterns RE2 rejects
          -- (lookaround/backref) fall back to ngx.re.match — never a silent
          -- drop. Detection-equivalent: RE2==PCRE captures verified across the
          -- CRS @rx corpus (5258 comparisons, 0 mismatch) + CRS regression
          -- empty-diff (flag OFF vs ON). Perf-neutral. Default ON; degrades to
          -- ngx.re when libka_re2.so is absent (ka_re2.available()).
          { engine_re2_match = { type = "boolean", default = true } },
          -- NOTE: three further engine optimizations are UNCONDITIONAL (no flag)
          -- because each is detection-neutral, proven by a CRS regression
          -- empty-diff (baseline 2755/2757): (1) skip body-requiring rules on a
          -- bodyless request, (2) per-request transform-cache hoist, (3) skip
          -- multipart-namespace scans on non-multipart bodies. Per project
          -- policy a sound (no-regression) optimization is not exposed as an
          -- optional toggle. See modules/ka_engine.lua for the implementations.
          { local_rules_enabled = { type = "boolean", default = true } },

          -- MCP (Model Context Protocol) — see modules/ka_mcp.lua.
          -- All off by default; the WAF behaves identically to non-MCP traffic
          -- until mcp_enabled is flipped on a route.
          { mcp_enabled = { type = "boolean", default = false } },
          { mcp_routes = { type = "array", elements = { type = "string" }, default = {} } },
          { mcp_detection_heuristic = { type = "boolean", default = false } },
          { mcp_protocol_versions_allowed = { type = "array", elements = { type = "string" },
              default = { "2025-11-25", "2025-06-18", "2025-03-26" } } },
          { mcp_block_legacy_sse_transport = { type = "boolean", default = false } },
          { mcp_origin_check_enabled = { type = "boolean", default = true } },
          { mcp_origins_allowed = { type = "array", elements = { type = "string" }, default = {} } },
          { mcp_max_event_size_bytes = { type = "number", default = 1048576 } },
          { mcp_max_stream_buffer_bytes = { type = "number", default = 8388608 } },
          { mcp_redact_session_id_in_audit = { type = "boolean", default = true } },
          { mcp_redact_authorization_in_audit = { type = "boolean", default = true } },
          { ignore_from_local_ips = { type = "boolean", default = false } },
          
          { check_invalid_chars_in_path = { type = "boolean", default = false } },
          { limit_invalid_chars_in_path = { type = "number", default = 1 } },
          { check_special_chars_in_path = { type = "boolean", default = true } },
          { limit_special_chars_in_path = { type = "number", default = 3 } },

          { request_methods_allowed = { type = "array", elements = { type = "string" }, default = { "GET","HEAD","PUT","POST","DELETE","OPTIONS","PATCH","PROPFIND" } } },
          { request_headers_denied = { type = "array", elements = { type = "string" }, default = { "content-encoding", "proxy", "lock-token", "content-range", "if" } } },
          { total_arg_value_length = { type = "number", default = 64000 } },

          -- restricted_extensions
          -- Aligned with the CRS 4.x default `tx.restricted_extensions`
          -- set (crs-setup.conf.example). Anything an operator does
          -- NOT want exposed via the URL path — secret keys
          -- (`.pem`, `.key`, `.crt`, `.pfx`), server-side config
          -- (`.config`, `.ini`, `.conf`), backup/working copies
          -- (`.bak`, `.swp`, `.old`), shell scripts (`.sh`, `.bat`,
          -- `.cmd`) — belongs here. Operators can shrink the list
          -- per-deployment via the plugin schema if it's too strict.
          { restricted_extensions = { type = "array", elements = { type = "string" }, default = { "ani", "asa", "asax", "ascx", "back", "backup", "bak", "bck", "bk", "bkp", "bat", "cdx", "cer", "cfg", "cnf", "cmd", "com", "compositefont", "config", "conf", "copy", "crt", "cs", "csproj", "csr", "dat", "db", "dbf", "dist", "dll", "dos", "dpkg-dist", "drv", "gadget", "hta", "htr", "htw", "ida", "idc", "idq", "inc", "inf", "ini", "jks", "jse", "key", "licx", "lnk", "log", "mdb", "msc", "ocx", "old", "pass", "pdb", "pem", "pfx", "pif", "pol", "prf", "printer", "pwd", "rdb", "rdp", "reg", "resources", "resx", "sav", "save", "scr", "sct", "sh", "shs", "sql", "sqlite", "sqlite3", "swap", "swo", "swp", "sys", "temp", "tfstate", "tlb", "tmp", "vb", "vbe", "vbs", "vbproj", "vsdisco", "vxd", "webinfo", "ws", "wsc", "wsf", "wsh", "xsd", "xsx", } } },

          -- allowed_request_content_type_charset
          -- default: |utf-8| |iso-8859-1| |iso-8859-15| |windows-1252|
          { request_content_type_charset_allowed = { type = "array", elements = { type = "string" }, default = { "utf-8", "iso-8859-1", "iso-8859-15", "windows-1252" } } },


          -- allowed_request_content_type
          -- |application/x-www-form-urlencoded| |multipart/form-data| |multipart/related| |text/xml| |application/xml| |application/soap+xml| |application/json| |application/cloudevents+json| |application/cloudevents-batch+json|
          { request_content_type_allowed = { type = "array", elements = { type = "string" }, default = { "application/x-www-form-urlencoded", "multipart/form-data", "multipart/related", "text/xml", "application/xml", "application/soap+xml", "application/json", "application/cloudevents+json", "application/cloudevents-batch+json" } } },

          -- request_content_type_enforce (default: true)
          -- When a request carries a non-empty body, require its
          -- Content-Type to be present and its base type (parameters
          -- stripped) to appear in request_content_type_allowed. A body
          -- with no Content-Type, or one Karna cannot structurally parse
          -- (text/plain, application/octet-stream, image/*, …) cannot be
          -- flattened into ARGS, so an attack smuggled inside it would skip
          -- inspection — a WAF bypass. "Deny what you can't inspect": block
          -- such bodies by default. Set false to restore the permissive
          -- behaviour for deployments that legitimately accept arbitrary
          -- body content types.
          { request_content_type_enforce = { type = "boolean", default = true } },

          -- arg_name_length (limit_arg_name_length)
          -- default: 100
          { limit_arg_name_length = { type = "number", default = 100 } },

          -- arg_length (limit_arg_value_length)
          -- default: 400
          { limit_arg_value_length = { type = "number", default = 400 } },

          -- limit_arg_num
          -- default 255
          { limit_arg_num = { type = "number", default = 255 } },

          { inspection_table_convert = { type = "array", elements = { type = "string" } } },
          { paranoia_level = { type = "number", default = 1 } },

          -- CRS-setup-style knobs. The bool/number is mapped at access-phase
          -- start into `kong.ctx.plugin.tx_variables.<crs_name>` so CRS rules
          -- written against ModSec's TX:<name> variables (e.g. 920250's
          -- `TX:CRS_VALIDATE_UTF8_ENCODING @eq 1`) resolve correctly without
          -- requiring crs-setup.conf. Defaults match the CRS recommended
          -- values for a strict posture.
          { validate_utf8_encoding = { type = "boolean", default = true } },

          -- CRS plugins (rule exclusions for specific apps — wordpress,
          -- drupal, nextcloud, phpbb, …). Karna reuses the upstream
          -- coreruleset-org plugin repos verbatim. The official Docker image
          -- includes the WordPress exclusions; operators can add others under
          -- `crs_plugins_path`. Each `crs_plugins_enabled` entry is the
          -- plugin's directory name under that path (e.g.
          -- "wordpress-rule-exclusions-plugin"). The .conf files under
          -- `<crs_plugins_path>/<name>/plugins/` are loaded via seclang.
          { crs_plugins_path = { type = "string", default = "/opt/coreruleset-plugins/" } },
          { crs_plugins_enabled = { type = "array", elements = { type = "string" }, default = {} } },

          -- Inline SecLang rule strings. Each entry is a single SecRule
          -- (or chained block) in ModSec syntax. Parsed via seclang at
          -- init_worker and added to the global rule pool. Use it for
          -- one-off exclusions or custom detection without dropping a
          -- .conf file on disk. JSON local rules in `rules_request`
          -- remain available for the same purpose; the two coexist.
          { custom_secrules = { type = "array", elements = { type = "string" }, default = {} } },

          -- All custom rules live here regardless of phase; the engine
          -- runs each in the phase named by its `phase` field (access /
          -- header_filter). There is deliberately no separate response
          -- array — the per-phase subset is precomputed and cached in
          -- handler.lua:get_local_request_rules, so a response-phase pass
          -- iterates only the response-phase rules, not the whole set.
          { rules_request = { type = "array", elements = { type = "string" } } },

          -- Per-rule action and response overrides — Karna's escape
          -- hatch for the "I trust this WAF, but for rule X I want to
          -- sanitize instead of block / send a custom 451 instead of
          -- 403" use case. Each entry is a JSON string with a
          -- `selector` (any combination of `ids`, `id_ranges`, `tags`,
          -- `except_ids`, `except_tags` — OR'd internally, except_*
          -- subtracts) and the override payload.
          --
          -- rule_action_overrides changes WHAT the rule does:
          --   { "selector": { "tags": ["attack-xss"] },
          --     "action":   { "type": "fix",
          --                   "remove_chars_pattern": "[<>\"'&;]" } }
          --   { "selector": { "ids": ["941100"] },
          --     "action":   { "type": "passthrough" } }
          --   { "selector": { "id_ranges": ["941000-941999"] },
          --     "action":   { "type": "block" } }
          --
          -- rule_response_overrides customises the response body /
          -- status / headers when the (possibly overridden) action is
          -- still a block. `body` is a static, operator-authored string
          -- served verbatim — no `%{var}` macro resolution, so request
          -- data is never reflected into the block response:
          --   { "selector": { "ids": ["920420"] },
          --     "response": { "status_code": 451,
          --                   "body": "Request refused.",
          --                   "headers": { "x-blocked-by": "karna" } } }
          --
          -- First matching entry wins (declaration order). The
          -- override mechanism never mutates the cached rule pack —
          -- the engine shallow-copies the matched rule and swaps its
          -- `action` per-request.
          { rule_action_overrides = { type = "array", elements = { type = "string" }, default = {} } },
          { rule_response_overrides = { type = "array", elements = { type = "string" }, default = {} } },

          -- Default block response — the page Karna serves whenever it
          -- blocks (CRS / local / custom rules AND the always-on
          -- validation gates) and nothing more specific was authored.
          -- `body` replaces the built-in plain-text bodies ("Forbidden",
          -- "Method Not Allowed", …); `headers` is merged over the
          -- built-in defaults (content-type text/plain + no-cache), with
          -- operator keys winning — set `content-type: text/html` here
          -- when the body is an HTML page. Status codes are NOT
          -- configurable: they stay semantic per block point (403 rules
          -- and most gates, 405 method gate, 400 arg-length gate, 429
          -- rate-limit). Anything more specific still wins: a rule's own
          -- `fixed_response` body/headers, a matching
          -- `rule_response_overrides` entry, a rate-limit rule's
          -- `response`. Like the override bodies, `body` is served
          -- verbatim — no `%{var}` macros, so request data is never
          -- reflected into the block page.
          { default_block_response_body = { type = "string" } },
          { default_block_response_headers = { type = "map",
              keys = { type = "string" }, values = { type = "string" },
              default = {} } },

          -- Default rate-limit response — a dedicated page for the 429
          -- served by the `rate_limit` rule action, so throttled (but
          -- legitimate) clients don't see the attack-block page. Body
          -- precedence: the rule's own `response` → these fields →
          -- default_block_response_* (back-compat: deployments that only
          -- set the block page keep today's behaviour) → built-in
          -- "Too Many Requests". Headers merge over the block chain with
          -- these keys winning; the automatic Retry-After stays unless
          -- explicitly overridden. Served verbatim — no `%{var}` macros
          -- (same reflected-input rationale as the block page).
          { default_ratelimit_response_body = { type = "string" } },
          { default_ratelimit_response_headers = { type = "map",
              keys = { type = "string" }, values = { type = "string" },
              default = {} } },

          -- Default 50x response — when the UPSTREAM answers 500-599,
          -- Karna replaces body and headers with this page (status code
          -- is preserved: a 502 stays a 502). Info-leak hygiene: stack
          -- traces, framework error pages, and server banners never reach
          -- the client. Setting `body` enables the feature; unset = 5xx
          -- responses pass through untouched. Applies only to responses
          -- that actually came from the upstream or Kong's error handler
          -- — never to responses generated by Karna itself or sibling
          -- plugins (kong.response.get_source() == "exit"). Independent
          -- of engine_blocking_mode (this is response hygiene, not attack
          -- blocking). `headers` merges over the built-in defaults
          -- (content-type text/plain + no-cache); it does NOT inherit
          -- default_block_response_headers. Served verbatim — no `%{var}`
          -- macros.
          { default_50x_response_body = { type = "string" } },
          { default_50x_response_headers = { type = "map",
              keys = { type = "string" }, values = { type = "string" },
              default = {} } },

          { try_bas64decode_if_possible = { type = "boolean", default = false } },

          { auditlog_enabled = { type = "boolean", default = true } },
          { auditlog_path = { type = "string", default = "/usr/local/openresty/nginx/logs" } },
          { auditlog_format = { type = "string", default = "v2", one_of = { "v1", "v2" } } },
          { auditlog_only_on_match = { type = "boolean", default = false } },
          { auditlog_modsec = { type = "boolean", default = false } },
          { auditlog_error_log_on_match = { type = "boolean", default = false } },

          { redis_host = { type = "string", default = "localhost" } },
          { redis_port = { type = "number", default = 6379 } },
          { redis_password = { type = "string" } },

          -- Redis rule-inspection (read-only): rules can read cluster-wide
          -- shared state via the `redis.*` variable namespace and the
          -- `redis_sismember` / `redis_hexists` operators. Off by default.
          { redis_inspect_enabled = { type = "boolean", default = false } },
          { redis_database = { type = "number", default = 0 } },
          { redis_timeout_ms = { type = "number", default = 50 } },
          { redis_keepalive_pool_size = { type = "number", default = 64 } },
          { redis_keepalive_idle_ms = { type = "number", default = 60000 } },
          -- What to do when a Redis read fails (down / timeout / wrong type):
          --   skip        condition = no-match, request flows (default; Redis is not a SPOF)
          --   fail_open   force the rule to NOT match
          --   fail_closed force the condition to match (deny on unreachable shared-state)
          { redis_on_error = { type = "string", default = "skip", one_of = { "skip", "fail_open", "fail_closed" } } },

          { private_debug = { type = "boolean", default = false } },
        },
        entity_checks = {
        },
      },
    },
  },
}

return schema
