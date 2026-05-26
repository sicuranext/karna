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

    -- CRS-compatibility bridges: rewrite CRS rules that depend on ModSec
    -- TX-side-effect variables (TX:/MULTIPART_HEADERS_*/, etc.) to target
    -- Karna's native multipart namespace instead. See
    -- ~/.claude/projects/.../memory/project_implementation_decisions.md
    -- and FINDINGS.md for the rationale: Karna's engine stays
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
            -- Karna's schema-level limit knobs. Architectural principle
            -- (memory: project_principle_config_vs_rules, 2026-05-24):
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