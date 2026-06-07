local _M = {}

_M.global_fps = {
    {
        id = "crs_global_fps_001",
        phase = "access",
        log = false,
        conditions = {
            {
                op = "beginsWith",
                transform = {},
                value = "/_oauth",
                variables = {"request.raw_path"}
            }
        },
        rule_control = {
            {
                remove_target_rule_by_tag = {
                    tag = "OWASP_CRS",
                    name = "request.query.value:state"
                }
            },
            {
                remove_target_rule_by_tag = {
                    tag = "OWASP_CRS",
                    name = "request.query.value:code"
                }
            },
            {
                remove_target_rule_by_tag = {
                    tag = "OWASP_CRS",
                    name = "request.query.value:scope"
                }
            },
            {
                remove_target_rule_by_tag = {
                    tag = "OWASP_CRS",
                    name = "request.query.value:authuser"
                }
            },
            {
                remove_target_rule_by_tag = {
                    tag = "OWASP_CRS",
                    name = "request.query.value:hd"
                }
            },
            {
                remove_target_rule_by_tag = {
                    tag = "OWASP_CRS",
                    name = "request.query.value:prompt"
                }
            }
        }
    },

    -- Coverage add (not a CRS-rule fix): CRS 944200 matches the RAW Java
    -- serialization magic bytes (\xac\xed\x00\x05), but the embedded NUL
    -- truncates the value in Karna's arg/body parsing, so the raw form is
    -- caught by other rules rather than 944200. The common real-world
    -- vector is those magic bytes base64-encoded inside a JSON / form /
    -- query field: "rO0AB..." (byte-aligned form) plus the two offset
    -- variants "KztAAU" / "Cs7QAF". This closes that gap globally. No PL
    -- tag -> active from PL1 (base64 Java serialization is a clear attack).
    {
        id = "crs_fix_java_serialization_b64",
        phase = "access",
        log = true,
        message = "Magic bytes Detected, probable java serialization in use (base64)",
        tags = { "attack-rce", "language-java", "platform-multi", "OWASP_CRS/ATTACK-JAVA" },
        conditions = {
            {
                op = "rx",
                transform = {},
                value = "(?:rO0AB|KztAAU|Cs7QAF)",
                variables = { "request.arg.value", "request.header.value" }
            }
        },
        action = {
            fixed_response = {
                status_code = 403,
                headers = {
                    ["content-type"] = "text/plain",
                    ["cache-control"] = "max-age=0, private, no-store, no-cache, must-revalidate"
                },
                body = "Forbidden\r\n"
            }
        }
    },

    -- CRS-compatibility bridges: rewrite CRS rules that depend on ModSec
    -- TX-side-effect variables (TX:/MULTIPART_HEADERS_*/, etc.) to target
    -- Karna's native multipart namespace instead. Karna's engine stays
    -- ModSec-generic; CRS-specific compatibility patches live here, in
    -- this file, where every override is auditable and versioned with
    -- each CRS release.
    -- CRS-compatibility bridge for rules that depend on `tx.allowed_methods`
    -- and other CRS-setup-time TX variables Karna doesn't initialise.
    --
    -- 911100 — `SecRule REQUEST_METHOD "!@within %{tx.allowed_methods}"`
    -- evaluates the macro to "" in Karna (no crs-setup.conf is loaded), so
    -- the operator becomes `!@within ""` which is true for every method
    -- (no method is inside the empty list) and the rule fires on every
    -- request. Karna's always-on `engine:method_allowed` gate provides the
    -- same coverage (request_methods_allowed config — see schema.lua),
    -- with a Karna-native synthetic rule id (`method_allowed`). The CRS
    -- rule id is therefore redundant; remove it.
    {
        id = "crs_compat_method_enforcement",
        phase = "access",
        log = false,
        conditions = {},
        unconditional_match_rule_control = {
            { remove_rule = { rule_id = "911100" } },

            -- 920360..920410 — CRS-config-gate rules that duplicate
            -- Karna's schema-level limit knobs. Architectural principle:
            -- limits and configuration live in the plugin schema,
            -- changeable on-the-fly via the Kong admin API. Detection
            -- rules detect attacks. The two never mix.
            --
            -- Each of these CRS rules is shaped as:
            --   SecRule &TX:<LIMIT> "@eq 1"  → gate: limit configured?
            --     SecRule <ARGS_VARIANT> "@gt %{tx.<limit>}"  → enforce
            -- which is `crs-setup.conf`-time policy expressed as a
            -- ModSec rule. Karna's equivalent is a plugin_conf field
            -- read by an always-on gate before the rule loop:
            --
            --   920360 ↔ plugin_conf.limit_arg_name_length
            --   920370 ↔ plugin_conf.limit_arg_value_length
            --   920380 ↔ plugin_conf.limit_arg_num
            --   920390 ↔ plugin_conf.total_arg_value_length
            --   920410 ↔ (body-length limit covers combined file sizes)
            --
            -- Removing the CRS rule pack avoids duplicate enforcement
            -- and keeps the operator UX in one place (schema only). The
            -- regression suite's per-rule tests are flagged as passed*
            -- via crs-regression-test/start.py's KARNA_REMOVED_RULES map.
            { remove_rule = { rule_id = "920360" } },
            { remove_rule = { rule_id = "920370" } },
            { remove_rule = { rule_id = "920380" } },
            { remove_rule = { rule_id = "920390" } },
            { remove_rule = { rule_id = "920410" } },

            -- 920450 — `SecRule REQUEST_HEADERS_NAMES "@rx ^.*$"
            -- chain SecRule TX:/^header_name_920450_/ "@within
            -- %{tx.restricted_headers_basic}"`. The chain captures
            -- every header name into a TX:/regex/ bag and checks
            -- against `tx.restricted_headers_basic`, which is the
            -- crs-setup.conf-time deny-list. Karna's equivalent is
            -- `plugin_conf.request_headers_denied` (default
            -- ["content-encoding", "proxy", "lock-token",
            -- "content-range", "if"]) enforced by the always-on
            -- `engine:check_request_headers_allowed` gate. The CRS
            -- rule pack is redundant; remove it.
            { remove_rule = { rule_id = "920450" } },

            -- 920650 — `SecRule TX:allow_method_override_parameter "@eq 0"`
            -- chained with `REQUEST_METHOD !@streq %{ARGS._method}`. The TX
            -- variable is a CRS-setup flag (defaulting to 0 in crs-setup.conf)
            -- that gates whether to *allow* request-method override via an
            -- `_method` query/body argument. Karna doesn't load crs-setup.conf,
            -- so the TX var is unset → the cond1 lookup yields no values →
            -- the chain never enters cond2 and the actual method-override
            -- detection silently doesn't run. Replace cond1 with
            -- `@unconditionalMatch` so the chain depends entirely on cond2,
            -- which is the real attack predicate. Karna users who *do* want
            -- to permit `_method` override per-service should add a local
            -- rule_control to remove 920650 instead.
            {
                replace_condition = {
                    rule_id = "920650",
                    condition_number = 1,
                    new_condition = {
                        multi_match = false,
                        op = "unconditionalMatch",
                        transform = {},
                        value = "",
                        variables = { "request.method" }
                    }
                }
            },
        }
    },

    -- Kong-API-gateway pruning of CRS 920/921/934 rules that are redundant or
    -- nonsensical when Karna runs as a Kong plugin in the access phase:
    --  * nginx/OpenResty already parses + rejects malformed HTTP (request line,
    --    Content-Length numeric/framing, CL+TE smuggling, Range framing, HTTP
    --    version) with a 400 before Karna ever runs;
    --  * Kong owns routing (Host) and the connection (Connection/keep-alive), so
    --    re-checking Host presence/emptiness/IP-form or Connection is meaningless;
    --  * Karna's schema already enforces content-type, charset and denied-headers
    --    as configurable limits (config-as-rule duplicates belong in the schema);
    --  * browser-nicety checks (missing/empty User-Agent or Accept, Cache-Control
    --    / Accept-Encoding / Accept-charset allow-lists, PL4 HPP array notation)
    --    false-positive on legitimate API/service clients;
    --  * CRS paranoia-level skipAfter / anomaly-scoring control markers are inert
    --    in Karna (no anomaly-score engine; PL handled separately).
    -- KEPT: every attack-content / evasion rule Kong does not inspect (injection,
    -- UTF-8 / unicode / multi-URL-encoding evasion, null/non-printable bytes,
    -- multipart filename bypass, backup-file access, SSRF, prototype pollution,
    -- SSTI, request smuggling/splitting via content, etc.). DELIBERATELY NOT
    -- pruned: 920340/920640 (missing-CT-with-body — guards body inspection),
    -- 920440 (file-extension policy, no schema equivalent), 920539/920540 (a
    -- functional ctl gate). Decided via a 5-agent analysis + adversarial security
    -- audit (zero detection gaps); the schema_dup removals assume the matching
    -- schema gates (defaulted) stay populated.
    {
        id = "crs_prune_kong_gateway",
        phase = "access",
        log = false,
        conditions = {},
        unconditional_match_rule_control = {
            -- protocol well-formedness (nginx/Kong already enforce)
            { remove_rule = { rule_id = "920100" } }, -- Invalid HTTP Request Line
            { remove_rule = { rule_id = "920160" } }, -- Content-Length not numeric
            { remove_rule = { rule_id = "920170" } }, -- GET/HEAD with body
            { remove_rule = { rule_id = "920171" } }, -- GET/HEAD with Transfer-Encoding
            { remove_rule = { rule_id = "920180" } }, -- POST without CL/TE
            { remove_rule = { rule_id = "920181" } }, -- CL + TE both present (smuggling framing)
            { remove_rule = { rule_id = "920190" } }, -- Range: invalid last byte
            { remove_rule = { rule_id = "920200" } }, -- Range: too many fields
            { remove_rule = { rule_id = "920201" } }, -- Range: too many fields (pdf 63+)
            { remove_rule = { rule_id = "920202" } }, -- Range: too many fields (pdf 6+, PL4)
            { remove_rule = { rule_id = "920430" } }, -- HTTP protocol version not allowed
            { remove_rule = { rule_id = "921230" } }, -- blanket HTTP Range header deny
            -- Host / connection semantics Kong owns
            { remove_rule = { rule_id = "920210" } }, -- Multiple/conflicting Connection header
            { remove_rule = { rule_id = "920280" } }, -- Missing Host header
            { remove_rule = { rule_id = "920290" } }, -- Empty Host header
            { remove_rule = { rule_id = "920350" } }, -- Host is a numeric IP
            -- browser-nicety / over-broad policy (FP on API clients)
            { remove_rule = { rule_id = "920300" } }, -- Missing Accept header
            { remove_rule = { rule_id = "920310" } }, -- Empty Accept header
            { remove_rule = { rule_id = "920311" } }, -- Empty Accept header (no UA)
            { remove_rule = { rule_id = "920320" } }, -- Missing User-Agent
            { remove_rule = { rule_id = "920330" } }, -- Empty User-Agent
            { remove_rule = { rule_id = "920510" } }, -- Invalid Cache-Control header
            { remove_rule = { rule_id = "920521" } }, -- Illegal Accept-Encoding header
            { remove_rule = { rule_id = "920600" } }, -- Illegal Accept charset parameter
            { remove_rule = { rule_id = "921220" } }, -- HPP via array notation (PL4)
            -- config-as-rule duplicated by Karna schema gates (defaulted)
            { remove_rule = { rule_id = "920400" } }, -- Uploaded file size (body-length limit covers)
            { remove_rule = { rule_id = "920420" } }, -- Content-type not allowed (request_content_type_allowed)
            { remove_rule = { rule_id = "920451" } }, -- Restricted header (request_headers_denied)
            { remove_rule = { rule_id = "920470" } }, -- Illegal Content-Type (request_content_type_allowed)
            { remove_rule = { rule_id = "920480" } }, -- Content-type charset not allowed (request_content_type_charset_allowed)
            -- CRS paranoia-level / anomaly-scoring control markers (inert in Karna)
            { remove_rule = { rule_id = "920011" } },
            { remove_rule = { rule_id = "920012" } },
            { remove_rule = { rule_id = "920013" } },
            { remove_rule = { rule_id = "920014" } },
            { remove_rule = { rule_id = "920015" } },
            { remove_rule = { rule_id = "920016" } },
            { remove_rule = { rule_id = "920017" } },
            { remove_rule = { rule_id = "920018" } },
            { remove_rule = { rule_id = "921011" } },
            { remove_rule = { rule_id = "921012" } },
            { remove_rule = { rule_id = "921013" } },
            { remove_rule = { rule_id = "921014" } },
            { remove_rule = { rule_id = "921015" } },
            { remove_rule = { rule_id = "921016" } },
            { remove_rule = { rule_id = "921017" } },
            { remove_rule = { rule_id = "921018" } },
            { remove_rule = { rule_id = "934011" } },
            { remove_rule = { rule_id = "934012" } },
            { remove_rule = { rule_id = "934013" } },
            { remove_rule = { rule_id = "934014" } },
            { remove_rule = { rule_id = "934015" } },
            { remove_rule = { rule_id = "934016" } },
            { remove_rule = { rule_id = "934017" } },
            { remove_rule = { rule_id = "934018" } },
        }
    },

    {
        id = "crs_compat_multipart",
        phase = "access",
        log = false,
        conditions = {},
        unconditional_match_rule_control = {
            -- 922110: Illegal MIME Multipart Header content-type charset.
            -- Original target TX:/MULTIPART_HEADERS_CONTENT_TYPES_*/ →
            -- Karna native request.body.multipart.part.content_type
            -- (multi-value: every part's Content-Type header value).
            -- Match semantics: !rx against the allowed-charsets pattern;
            -- a Content-Type with a non-allowed charset fails the match,
            -- !rx triggers, the rule fires.
            {
                replace_condition = {
                    rule_id = "922110",
                    condition_number = 1,
                    new_condition = {
                        multi_match = true,
                        op = "rx",
                        negated = true,
                        transform = { "lowercase" },
                        -- media/subtype, optionally followed by:
                        --   a charset clause whose value MUST be one of
                        --   the four CRS-allowed charsets,
                        --   AND/OR any number of other `name=value`
                        --   parameter clauses (e.g. `boundary=inner` on
                        --   a multipart part).
                        -- Order is fixed (charset before others) which
                        -- mirrors the canonical RFC 2045 ordering used
                        -- by every common client.
                        value = "^[^;\\s/]+/[^;\\s/]+(?:\\s*;\\s*charset\\s*=\\s*\"?(?:utf-8|iso-8859-15?|windows-1252)\"?)?(?:\\s*;\\s*(?!charset\\s*=)[^=;\\s]+\\s*=\\s*[^;]+)*\\s*$",
                        variables = { "request.body.multipart.part.content_type" }
                    }
                }
            },
        }
    }
}

return _M