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
          { ignore_from_local_ips = { type = "boolean", default = true } },
          
          { check_invalid_chars_in_path = { type = "boolean", default = false } },
          { limit_invalid_chars_in_path = { type = "number", default = 1 } },
          { check_special_chars_in_path = { type = "boolean", default = true } },
          { limit_special_chars_in_path = { type = "number", default = 3 } },

          { request_methods_allowed = { type = "array", elements = { type = "string" }, default = { "GET","HEAD","PUT","POST","DELETE","OPTIONS","PATCH","PROPFIND" } } },
          { request_headers_denied = { type = "array", elements = { type = "string" }, default = { "content-encoding", "proxy", "lock-token", "content-range", "if" } } },
          { total_arg_value_length = { type = "number", default = 64000 } },

          -- restricted_extensions
          -- default: .asa/ .asax/ .ascx/ .backup/ .bak/ .bat/ .cdx/ .cer/ .cfg/ .cmd/ .com/ .config/ .conf/ .cs/ .csproj/ .csr/ .dat/ .db/ .dbf/ .dll/ .dos/ .htr/ .htw/ .ida/ .idc/ .idq/ .inc/ .ini/ .key/ .licx/ .lnk/ .log/ .mdb/ .old/ .pass/ .pdb/ .pol/ .printer/ .pwd/ .rdb/ .resources/ .resx/ .sql/ .swp/ .sys/ .vb/ .vbs/ .vbproj/ .vsdisco/ .webinfo/ .xsd/ .xsx/
          { restricted_extensions = { type = "array", elements = { type = "string" }, default = { "asa", "asax", "ascx", "backup", "bak", "bat", "cdx", "cer", "cfg", "cmd", "com", "config", "conf", "cs", "csproj", "csr", "dat", "db", "dbf", "dll", "dos", "htr", "htw", "ida", "idc", "idq", "inc", "ini", "key", "licx", "lnk", "log", "mdb", "old", "pass", "pdb", "pol", "printer", "pwd", "rdb", "resources", "resx", "sql", "swp", "sys", "vb", "vbs", "vbproj", "vsdisco", "webinfo", "xsd", "xsx", } } },

          -- allowed_request_content_type_charset
          -- default: |utf-8| |iso-8859-1| |iso-8859-15| |windows-1252|
          { request_content_type_charset_allowed = { type = "array", elements = { type = "string" }, default = { "utf-8", "iso-8859-1", "iso-8859-15", "windows-1252" } } },


          -- allowed_request_content_type
          -- |application/x-www-form-urlencoded| |multipart/form-data| |multipart/related| |text/xml| |application/xml| |application/soap+xml| |application/json| |application/cloudevents+json| |application/cloudevents-batch+json|
          { request_content_type_allowed = { type = "array", elements = { type = "string" }, default = { "application/x-www-form-urlencoded", "multipart/form-data", "multipart/related", "text/xml", "application/xml", "application/soap+xml", "application/json", "application/cloudevents+json", "application/cloudevents-batch+json" } } },

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
          -- coreruleset-org plugin repos verbatim (we don't ship them):
          -- the operator clones them into `crs_plugins_path` and lists
          -- the ones to load in `crs_plugins_enabled`. Each entry is the
          -- plugin's directory name under `crs_plugins_path` (e.g.
          -- "wordpress-rule-exclusions-plugin"). The .conf files under
          -- `<crs_plugins_path>/<name>/plugins/` are loaded via seclang
          -- alongside the OWASP CRS rule pack.
          { crs_plugins_path = { type = "string", default = "/opt/coreruleset-plugins/" } },
          { crs_plugins_enabled = { type = "array", elements = { type = "string" }, default = {} } },

          -- Inline SecLang rule strings. Each entry is a single SecRule
          -- (or chained block) in ModSec syntax. Parsed via seclang at
          -- init_worker and added to the global rule pool. Use it for
          -- one-off exclusions or custom detection without dropping a
          -- .conf file on disk. JSON local rules in `rules_request`
          -- remain available for the same purpose; the two coexist.
          { custom_secrules = { type = "array", elements = { type = "string" }, default = {} } },

          { rules_request = { type = "array", elements = { type = "string" } } },
          { rules_response = { type = "array", elements = { type = "string" } } },

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
          -- still a block. `body` supports `%{var}` template macros
          -- resolved against the current request:
          --   { "selector": { "ids": ["920420"] },
          --     "response": { "status_code": 451,
          --                   "body": "Refused: %{request.remote_addr}",
          --                   "headers": { "x-blocked-by": "karna" } } }
          --
          -- First matching entry wins (declaration order). The
          -- override mechanism never mutates the cached rule pack —
          -- the engine shallow-copies the matched rule and swaps its
          -- `action` per-request.
          { rule_action_overrides = { type = "array", elements = { type = "string" }, default = {} } },
          { rule_response_overrides = { type = "array", elements = { type = "string" }, default = {} } },

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

          { private_debug = { type = "boolean", default = false } },
        },
        entity_checks = {
        },
      },
    },
  },
}

return schema
