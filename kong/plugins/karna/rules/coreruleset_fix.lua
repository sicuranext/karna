local _M = {}

_M.rule_crs_fix_4_0 = {
    id = "100",
    phase = "access",
    --[[conditions = {
        {
            multi_match = false,
            op = "beginsWith",
            transform = { "none" },
            value = "/",
            variables = { "request.raw_path" }
        }
    },]]--
    conditions = {},
    unconditional_match_rule_control = {
        {
            remove_rule = {
                rule_id = "932236"
            }
        },
        {
            remove_rule = {
                rule_id = "920480"
            }
        },
        {
            remove_rule = {
                rule_id = "920450"
            }
        },

        -- that's crazy... match id like
        -- id=1 or foo=id
        {
            remove_rule = {
                rule_id = "932239"
            }
        },
        -- matching:
        -- request.cookie.value:foo - Matched value: 0|for
        -- request.cookie.value:_clck - Matched value: 5rspta|2|for|0|1518
        {
            change_condition_variables = {
                rule_id = "932380",
                condition_number = 1,
                new_variables = { "request.arg.name", "request.arg.value" }
            }
        },

        -- fix 942100
        -- old vars: { "request.cookie.value", "request.cookie.name", "request.header.value:User-Agent", "request.header.value:Referer", "request.arg.name", "request.arg.value" }
        -- new vars: { "request.cookie.value", "request.cookie.name", "request.arg.name", "request.arg.value" }
        {
            change_condition_variables = {
                rule_id = "942100",
                condition_number = 1,
                new_variables = { "request.cookie.value", "request.cookie.name", "request.arg.name", "request.arg.value" }
            }
        },

        -- removing 922110 checks for charset parameter in 
        -- multipart message content-type header
        -- since it could be empty, this rule produce a lot of FPs
        -- without any real benefit
        {
            remove_rule = {
                rule_id = "922110"
            }
        },

        {
            change_condition_tfunc = {
                rule_id = "920250",
                condition_number = 1,
                new_tfunc = {}
            }
        },

        {
            change_condition_value = {
                rule_id = "932205",
                condition_number = 1,
                new_value = "^([^#]+)"
            }
        },

        -- 920230
        {
            change_condition_tfunc = {
                rule_id = "920230",
                condition_number = 1,
                new_tfunc = {}
            }
        },

        -- 920330
        {
            change_rule_action = {
                rule_id = "920330",
                action = {
                    fixed_response = {
                        body = "Forbidden",
                        headers = {
                            ["cache-control"] = "max-age=0, private, no-store, no-cache, must-revalidate",
                            ["content-type"] = "text/plain"
                        },
                        status_code = 403
                    },
                }
            }
        },

        {
            change_condition_tfunc = {
                rule_id = "920250",
                condition_number = 3,
                new_tfunc = {}
            }
        },
        {
            -- 920100
            change_condition_tfunc = {
                rule_id = "920100",
                condition_number = 1,
                new_tfunc = {}
            }
        },
        {
            change_condition_tfunc = {
                rule_id = "930100",
                condition_number = 1,
                new_tfunc = {"removeNulls"}
            }
        },
        {
            change_condition_tfunc = {
                rule_id = "920221",
                condition_number = 3,
                new_tfunc = {}
            }
        },
        {
            replace_condition = {
                rule_id = "920340",
                condition_number = 3,
                new_condition = {
                    multi_match = false,
                    op = "!isSet",
                    transform = {},
                    value = "",
                    variables = { "request.header.value:content-type" }
                }
            }
        },
        {
            change_rule_action = {
                rule_id = "920340",
                action = {
                    fixed_response = {
                        body = "Forbidden",
                        headers = {
                            ["cache-control"] = "max-age=0, private, no-store, no-cache, must-revalidate",
                            ["content-type"] = "text/plain"
                        },
                        status_code = 403
                    },
                }
            }
        },

        -- 920320
        {
            change_rule_action = {
                rule_id = "920320",
                action = {
                    fixed_response = {
                        body = "Forbidden",
                        headers = {
                            ["cache-control"] = "max-age=0, private, no-store, no-cache, must-revalidate",
                            ["content-type"] = "text/plain"
                        },
                        status_code = 403
                    },
                }
            }
        },
        {
            replace_condition = {
                rule_id = "920320",
                condition_number = 1,
                new_condition = {
                    multi_match = false,
                    op = "!isSet",
                    transform = {},
                    value = "",
                    variables = { "request.header.value:user-agent" }
                }
            }
        },

        -- 920310
        {
            change_rule_action = {
                rule_id = "920310",
                action = {
                    fixed_response = {
                        body = "Forbidden",
                        headers = {
                            ["cache-control"] = "max-age=0, private, no-store, no-cache, must-revalidate",
                            ["content-type"] = "text/plain"
                        },
                        status_code = 403
                    },
                }
            }
        },
        -- remove tfunc from 920610
        {
            change_condition_tfunc = {
                rule_id = "920610",
                condition_number = 1,
                new_tfunc = {}
            }
        },

        -- 920311
        {
            replace_condition = {
                rule_id = "920311",
                condition_number = 4,
                new_condition = {
                    multi_match = false,
                    op = "!isSet",
                    transform = {},
                    value = "",
                    variables = { "request.header.value:user-agent" }
                }
            }
        },

        {
            change_rule_action = {
                rule_id = "920311",
                action = {
                    fixed_response = {
                        body = "Forbidden",
                        headers = {
                            ["cache-control"] = "max-age=0, private, no-store, no-cache, must-revalidate",
                            ["content-type"] = "text/plain"
                        },
                        status_code = 403
                    },
                }
            }
        },
        -- 920180 condition 4 !isSet request.header.value:content-length
        -- 920180 condition 5 !isSet request.header.value:transfer-encoding
        {
            replace_condition = {
                rule_id = "920180",
                condition_number = 4,
                new_condition = {
                    multi_match = false,
                    op = "!isSet",
                    transform = {},
                    value = "",
                    variables = { "request.header.value:content-length" }
                }
            }
        },
        {
            replace_condition = {
                rule_id = "920180",
                condition_number = 5,
                new_condition = {
                    multi_match = false,
                    op = "!isSet",
                    transform = {},
                    value = "",
                    variables = { "request.header.value:transfer-encoding" }
                }
            }
        },

        -- 920470 set tfunc to {"lowercase"} for condition 1
        {
            change_condition_tfunc = {
                rule_id = "920470",
                condition_number = 1,
                new_tfunc = {"lowercase"}
            }
        },

        -- 921422 set tfunc to {"lowercase"} for condition 1
        {
            change_condition_tfunc = {
                rule_id = "921421",
                condition_number = 1,
                new_tfunc = {"lowercase"}
            }
        },
        {
            change_condition_tfunc = {
                rule_id = "921422",
                condition_number = 1,
                new_tfunc = {"lowercase"}
            }
        },

        -- 921140 set tfunc to {"htmlEntityDecode"} for condition 1
        {
            change_condition_tfunc = {
                rule_id = "921140",
                condition_number = 1,
                new_tfunc = {"htmlEntityDecode"}
            }
        },

        -- 943120 replace condition 3 with !isSet request.header.value:referer
        {
            replace_condition = {
                rule_id = "943120",
                condition_number = 3,
                new_condition = {
                    multi_match = false,
                    op = "!isSet",
                    transform = {},
                    value = "",
                    variables = { "request.header.value:referer" }
                }
            }
        },

        -- 920341 replace condition 3 with !isSet request.header.value:content-type
        {
            replace_condition = {
                rule_id = "920341",
                condition_number = 3,
                new_condition = {
                    multi_match = false,
                    op = "!isSet",
                    transform = {},
                    value = "",
                    variables = { "request.header.value:content-type" }
                }
            }
        },
        {
            add_condition = {
                rule_id = "920341",
                condition = {
                    multi_match = false,
                    op = "isSet",
                    transform = {},
                    value = "",
                    variables = { "request.header.value:content-length" }
                }
            }
        },

        -- 920600 add_condition isset REQUEST_HEADERS:Accept
        {
            add_condition = {
                rule_id = "920600",
                condition = {
                    multi_match = false,
                    op = "isSet",
                    transform = {},
                    value = "",
                    variables = { "request.header.value:accept" }
                }
            }
        },

        -- 920451
        {
            replace_condition = {
                rule_id = "920451",
                condition_number = 3,
                new_condition = {
                    multi_match = false,
                    op = "isSet",
                    transform = {},
                    value = "",
                    variables = { "var:request_headers_denied" }
                }
            }
        },

        -- 920390 remove condition 1
        {
            remove_condition = {
                rule_id = "920390",
                condition_number = 1
            }
        },

        -- 920221 replace condition 3
        {
            replace_condition = {
                rule_id = "920221",
                condition_number = 3,
                new_condition = {
                    multi_match = false,
                    op = "validateUrlEncoding",
                    transform = {},
                    value = "",
                    variables = { "request.basename" }
                }
            }
        },

        -- 941310 replace tfunc on condition 1
        {
            change_condition_tfunc = {
                rule_id = "941310",
                condition_number = 1,
                new_tfunc = {"lowercase", "urlDecode", "escapeSeqDecode", "htmlEntityDecode", "jsDecode"}
            }
        },
        {
            change_condition_tfunc = {
                rule_id = "941310",
                condition_number = 3,
                new_tfunc = {"lowercase", "urlDecode", "escapeSeqDecode", "htmlEntityDecode", "jsDecode"}
            }
        },


        -- 922110 replace condition 1 request.body.multipart.header.raw
        {
            replace_condition = {
                rule_id = "922110",
                condition_number = 1,
                new_condition = {
                    multi_match = false,
                    op = "rx",
                    transform = {"urlDecodeUni", "lowercase"},
                    value = "^content-type\\s*:\\s*(.*)$",
                    variables = { "request.body.multipart.header.raw" }
                }
            }
        },

        
        -- 922120 replace condition 1 request.body.multipart.header.raw
        {
            replace_condition = {
                rule_id = "922120",
                condition_number = 1,
                new_condition = {
                    multi_match = false,
                    op = "rx",
                    transform = {"urlDecodeUni", "lowercase"},
                    value = "content-transfer-encoding:(.*)",
                    variables = { "request.body.multipart.header.raw" }
                }
            }
        },

        
        -- 922100 replace condition 1 isSet request.body.multipart.name:_charset_
        {
            replace_condition = {
                rule_id = "922100",
                condition_number = 1,
                new_condition = {
                    multi_match = false,
                    op = "isSet",
                    transform = {},
                    value = "",
                    variables = { "request.body.multipart.name:_charset_" }
                }
            }
        },


        -- 922100 replace condition 2 request.body.multipart.value:_charset_
        {
            replace_condition = {
                rule_id = "922100",
                condition_number = 2,
                new_condition = {
                    multi_match = false,
                    op = "!within",
                    transform = {"urlDecodeUni", "lowercase"},
                    value = "%{tx.allowed_request_content_type_charset}",
                    variables = { "request.body.multipart.value:_charset_" }
                }
            }
        },

        -- 944120 replace condition 1
        {
            replace_condition = {
                rule_id = "944120",
                condition_number = 1,
                new_condition = {
                    multi_match = false,
                    op = "rx",
                    transform = {"urlDecodeUni", "lowercase"},
                    value = "(?:clonetransformer|forclosure|instantiatefactory|instantiatetransformer|invokertransformer|prototypeclonefactory|prototypeserializationfactory|whileclosure|getproperty|filewriter|xmldecoder)",
                    variables = { "request.arg.value", "request.arg.name", "request.cookie.value", "request.cookie.name", "request.header.value", "request.raw_body_if_type_unknown" }
                }
            }
        },

        -- 944210 replace condition 1
        {
            replace_condition = {
                rule_id = "944210",
                condition_number = 1,
                new_condition = {
                    multi_match = false,
                    op = "rx",
                    transform = {"urlDecodeUni"},
                    value = "(?:rO0ABQ|KztAAU|Cs7QAF)",
                    variables = { "request.arg.value", "request.arg.name", "request.cookie.value", "request.cookie.name", "request.raw_body_if_type_unknown", "request.header.value" }
                }
            }
        },

        -- 932140 replace tfunc on condition 1
        --[[{
            change_condition_tfunc = {
                rule_id = "932140",
                condition_number = 1,
                new_tfunc = { "cmdLine" }
            }
        },]]--

        -- 911100 remove rule
        {
            remove_rule = {
                rule_id = "911100"
            }
        },

        -- 920190 replace rule operator to grx
        {
            replace_condition = {
                rule_id = "920190",
                condition_number = 1,
                new_condition = {
                    multi_match = false,
                    op = "grx",
                    transform = {"urlDecodeUni"},
                    value = "(\\d+)-(\\d+)",
                    variables = { "request.header.value:Range", "request.header.value:Request-Range" }
                }
            }
        },

        -- 920230 replace tfunc on condition 1
        {
            change_condition_tfunc = {
                rule_id = "920230",
                condition_number = 1,
                new_tfunc = { "hexSequenceDecode" }
            }
        },

        -- 920260 remove tfunc on condition 1
        {
            change_condition_tfunc = {
                rule_id = "920260",
                condition_number = 1,
                new_tfunc = {}
            }
        },

        -- 920310 add condition
        {
            add_condition = {
                rule_id = "920310",
                condition = {
                    multi_match = false,
                    op = "isSet",
                    transform = {},
                    value = "",
                    variables = { "request.header.value:user-agent" }
                }
            }
        },

        -- 920420 replace condition 1
        {
            replace_condition = {
                rule_id = "920420",
                condition_number = 1,
                new_condition = {
                    multi_match = false,
                    op = "rx",
                    transform = {},
                    value = "^([^;\\s]+)",
                    variables = { "request.header.value:content-type" }
                }
            }
        },

        -- 920420 replace condition 3
        {
            replace_condition = {
                rule_id = "920420",
                condition_number = 3,
                new_condition = {
                    multi_match = false,
                    op = "!within",
                    transform = {"lowercase"},
                    value = "%{tx.allowed_request_content_type}",
                    variables = { "group:1" }
                }
            }
        },

        -- 920450 replace condition 1
        {
            replace_condition = {
                rule_id = "920450",
                condition_number = 1,
                new_condition = {
                    multi_match = false,
                    op = "rx",
                    transform = {"lowercase"},
                    value = "^(.*)$",
                    variables = { "request.header.name" }
                }
            }
        },

        -- 920540 replace condition 1
        {
            replace_condition = {
                rule_id = "920540",
                condition_number = 1,
                new_condition = {
                    multi_match = false,
                    op = "!eq",
                    transform = {"lowercase"},
                    value = "json",
                    variables = { "request.body.processor" }
                }
            }
        },
        -- 920540 change condition 3 tfunc
        {
            change_condition_tfunc = {
                rule_id = "920540",
                condition_number = 3,
                new_tfunc = {"hexSequenceDecode"}
            }
        },

        -- 933110 replace condition 1
        {
            replace_condition = {
                rule_id = "933110",
                condition_number = 1,
                new_condition = {
                    multi_match = false,
                    op = "rx",
                    transform = {"urlDecodeUni", "lowercase"},
                    value = ".*\\.ph(?:p\\d*|tml|ar|ps|t|pt)(?:[.]*)?$",
                    variables = { "request.file", "request.header.value:X-Filename", "request.header.value:X_Filename", "request.header.value:X.Filename", "request.header.value:X-File-Name" }
                }
            }
        },

        -- 934120 change condition 1 tfunc
        {
            change_condition_tfunc = {
                rule_id = "934120",
                condition_number = 1,
                new_tfunc = {"hexSequenceDecode"}
            }
        },

        -- 942450 change condition 1 tfunc using hexSequenceDecode
        {
            change_condition_tfunc = {
                rule_id = "942450",
                condition_number = 1,
                new_tfunc = {"hexSequenceDecode"}
            }
        },




        -- patching condition due to modsecurity missing isset operator

        -- 920171 replace condition 3
        {
            replace_condition = {
                rule_id = "920171",
                condition_number = 3,
                new_condition = {
                    multi_match = false,
                    op = "isSet",
                    transform = {},
                    value = "",
                    variables = { "request.header.value:transfer-encoding" }
                }
            }
        },

        -- 920181 replace condition 1 and 3
        {
            replace_condition = {
                rule_id = "920181",
                condition_number = 1,
                new_condition = {
                    multi_match = false,
                    op = "isSet",
                    transform = {},
                    value = "",
                    variables = { "request.header.value:transfer-encoding" }
                }
            }
        },
        {
            replace_condition = {
                rule_id = "920181",
                condition_number = 3,
                new_condition = {
                    multi_match = false,
                    op = "isSet",
                    transform = {},
                    value = "",
                    variables = { "request.header.value:content-length" }
                }
            }
        },

        -- 920340 add condition
        {
            add_condition = {
                rule_id = "920340",
                condition = {
                    multi_match = false,
                    op = "isSet",
                    transform = {},
                    value = "",
                    variables = { "request.header.value:content-length" }
                }
            }
        },

        {
            remove_condition = {
                rule_id = "920340",
                condition_number = 1
            }
        },

        -- 920470 add condition
        {
            add_condition = {
                rule_id = "920470",
                condition = {
                    multi_match = false,
                    op = "isSet",
                    transform = {},
                    value = "",
                    variables = { "request.header.value:content-type" }
                }
            }
        },

        -- 920160 add condition
        {
            add_condition = {
                rule_id = "920160",
                condition = {
                    multi_match = false,
                    op = "isSet",
                    transform = {},
                    value = "",
                    variables = { "request.header.value:content-length" }
                }
            }
        },

    },
    log = false,
    message = "CRS Fix"
}

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
    }
}

return _M