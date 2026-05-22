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
                        op = "!rx",
                        transform = { "lowercase" },
                        value = "^[^;\\s/]+/[^;\\s/]+(?:\\s*;\\s*charset\\s*=\\s*\"?(?:utf-8|iso-8859-15?|windows-1252)\"?\\s*)?$",
                        variables = { "request.body.multipart.part.content_type" }
                    }
                }
            },
        }
    }
}

return _M