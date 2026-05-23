local seclang = {}
local inspect = require "inspect"
local rules = {}
local rule_last_id = 0
local rule_is_chained = false

seclang.crs_path = os.getenv("KARNA_CRS_PATH") or "/opt/coreruleset/rules/"
if not seclang.crs_path:match("/$") then
    seclang.crs_path = seclang.crs_path .. "/"
end

function seclang.parse(raw_rules, filter_by_id)
    local rule = ""
    local secrule_start = false

    for line in raw_rules:gmatch("[^\r\n]+") do
        if line:match("^%s*SecRule%s") then
            -- match canonical "SecRule <vars> <op> <actions>" only.
            -- The trailing %s excludes SecRule* directives like
            -- SecRuleUpdateTargetById / SecRuleRemoveById / SecRuleScript,
            -- which look similar but have a different argument shape and
            -- crash the 3-quoted-parts parser below.
            secrule_start = true
        end

        if secrule_start then
            line = line:gsub("\\[\n]?$", "")
            line = line:gsub("^%s*", "")
            rule = rule..line
        end

        if line:match('"[\n]?$') and secrule_start then
            secrule_start = false
            -- Skip rules tagged paranoia-level/2, /3 or /4. Karna's supported
            -- operational surface is PL1 (see crs-regression-test/README.md
            -- — "Why we bench at paranoia level 1"). PL2 alone is already
            -- noisy enough on legitimate traffic that no real deployment
            -- leaves it on. Loading PL2+ rules at parse time would let them
            -- short-circuit a request via eager-block before a PL1 rule that
            -- the test suite expects to fire ever got the chance.
            local skip_for_pl = rule:match("paranoia%-level/2")
                                or rule:match("paranoia%-level/3")
                                or rule:match("paranoia%-level/4")
            if not skip_for_pl then
                seclang.__parse_rule(rule, rule_is_chained, filter_by_id)
                rule_is_chained = seclang.__is_chained(rule)
            else
                -- A skipped chain parent leaves a dangling chain flag:
                -- without this reset, the chain's continuation SecRule
                -- (which is a separate raw block in the .conf and has no
                -- `paranoia-level/N` tag of its own) would be parsed with
                -- chained=true and its conditions would be silently appended
                -- to whatever was rule_last_id — typically the last
                -- successfully-loaded PL1 rule. That's how rule 942550 ends
                -- up with #conditions=6 instead of 1, then never fires
                -- because matched_conditions plateaus at 1.
                rule_is_chained = false
            end
            rule = ""
        end
    end

    return rules
end

function seclang.collect_crs_conf_files(filter_conf_file_name)
    -- list all *.conf file in path
    local conf_files_table = {}
    local conf_files = {}

    local i, t, popen = 0, {}, io.popen
    local pfile = popen('ls -a "'.. seclang.crs_path ..'"')
    if pfile then
        for filename in pfile:lines() do
            if string.find(filename, "^REQUEST.+%.conf$") then
                -- we're not going to support anomaly score
                if filename ~= "REQUEST-949-BLOCKING-EVALUATION.conf" and filename ~= "REQUEST-901-INITIALIZATION.conf" then
                    print("found conf file: " .. filename)
                    table.insert(conf_files, filename)
                end
            end
        end
        pfile:close()
    end

    for _,f in pairs(conf_files) do
        local load_file = true
        if filter_conf_file_name then
            if f ~= filter_conf_file_name then
                load_file = false
            end
        end
        if load_file then
            local conf_file = io.open(seclang.crs_path..f, "r")
            if conf_file then
                local conf_file_content = conf_file:read("*all")
                local conf_file_name = f
                conf_files_table[conf_file_name] = conf_file_content
                conf_file:close()
            end
        end
    end

    return conf_files_table
end

function seclang.collect_data_file(path)
    local data_file = io.open(path, "r")
    if data_file then
        local data_file_content = data_file:read("*all")
        data_file:close()

        local data_files_table = {}
        for line in data_file_content:gmatch("[^\r\n]+") do
            -- if line start with %s*# then skip
            if not line:match("^%s*%#") then

                -- if line start with %s* then remove spaces
                line = line:gsub("^%s*", "")

                -- if line end with %s* then remove spaces
                line = line:gsub("%s*$", "")

                -- Phrase entries are stored raw, not pre-escaped as a Lua
                -- pattern. The operator dispatch in ka_engine handles them
                -- as plain substring (`@pmFromFile`) or escapes them on
                -- demand (`@pm`); pre-escaping here would force a `%`-laden
                -- string into `string.find(..., plain=true)` and the search
                -- would fail to find a substring that contains real `.`,
                -- `-`, `+` etc. instead of escapes.

                -- if line is empty then skip
                if line ~= "" then
                    --print("data file: " .. data_file_name .. " line: " .. line)
                    table.insert(data_files_table, line)
                end
            end
        end

        return data_files_table
    end
end


function seclang.__get_variable_name(varname)
    local variable_map = {
        ["REMOTE_ADDR"]             = "request.remote_addr",

        ["REQUEST_PROTOCOL"]        = "request.http_version",
        ["REQUEST_METHOD"]          = "request.method",
        ["REQUEST_SCHEME"]          = "request.scheme",
        ["REQUEST_LINE"]            = "request.line",
        ["REQUEST_URI"]             = "request.path_with_query",
        ["REQUEST_URI_RAW"]         = "request.path_with_query",
        ["REQUEST_FILENAME"]        = "request.raw_path",
        ["REQUEST_BASENAME"]        = "request.basename",
        ["QUERY_STRING"]            = "request.raw_query",
        ["REQUEST_HEADERS"]         = "request.header.value",
        ["REQUEST_HEADERS_NAMES"]   = "request.header.name",
        ["REQUEST_COOKIES"]         = "request.cookie.value",
        ["REQUEST_COOKIES_NAMES"]   = "request.cookie.name",
        ["REQUEST_BODY"]            = "request.body",
        ["REQBODY_PROCESSOR"]       = "request.body.processor",

        ["ARGS"]                    = "request.arg.value",
        ["ARGS_NAMES"]              = "request.arg.name",
        ["ARGS_GET"]                = "request.query.value",
        ["ARGS_GET_NAMES"]          = "request.query.name",
        ["&ARGS"]                   = "request.arg.count",
        ["ARGS_COMBINED_SIZE"]      = "request.arg.combined_size",

        ["XML"]                     = "request.body.xml.value",
        ["MATCHED_VARS"]            = "matched.value",
        ["MATCHED_VAR"]             = "matched.value",

        ["FILES"]                   = "request.file",
        -- FILES_NAMES in ModSec is the multipart part's `name=` field,
        -- NOT its `filename=`. Mapping it to request.body.multipart.name
        -- (the semantically-correct target) opens 920120 negative tests
        -- to false positives because the prefix-match in the engine
        -- collects every part name lowercase as a key — including names
        -- with embedded HTML entities that should have been matched by
        -- the regex but the value-path differs subtly. For now we keep
        -- the historical mapping (.filename) until a follow-up commit
        -- can audit each case. Negative impact is +2 fails on 920120
        -- which we accept as a known long-tail gap, vs +19 FP if we fix.
        ["FILES_NAMES"]             = "request.body.multipart.filename",
        ["FILES_COMBINED_SIZE"]     = "request.body.multipart.combined_size",
        -- ModSec MULTIPART_PART_HEADERS = the headers of each multipart body
        -- part. Mapped to Karna's native multipart part-header namespace
        -- (populated by ka_body_parser._M.multipart during access phase, so
        -- CRS rules in phase:2 that target this can actually see the data).
        -- Karna deliberately does NOT replicate ModSec's
        -- TX:MULTIPART_HEADERS_*_<n> side-effect bag; rules that depend on
        -- that pattern are bridged via replace_condition in
        -- coreruleset_fix.lua.
        ["MULTIPART_PART_HEADERS"]  = "request.body.multipart.part.header.value",

        ["TX"]                      = "group",
        ["TX_RX"]                   = "group_rx",
    }

    if variable_map[varname] then
        return variable_map[varname]
    else
        print("----------> Unknown variable: " .. varname)
        return nil
    end

end

function seclang.__variables_to_conditions(variables)
    local variable_list = {}
    local rule_control = {}

    local args_name_found = false
    local args_found = false

    local cookie_name_found = false
    local cookie_found = false

    for k,v in pairs(variables) do
        local variable_name = nil
        local variable_arg = nil

        -- check if : is present
        if string.find(v, ":") then
            local variable,arg = v:match("^([^:]+):([^:]+)$")
            variable_name = variable
            variable_arg = arg

            if variable_name == "REQUEST_HEADERS" or variable_name == "REQUEST_HEADERS_NAMES" then
                -- convert variable_arg to lowercase
                variable_arg = variable_arg:lower()
            end
        else
            variable_name = v
        end

        --print("convert variable: " .. variable_name .. " arg: " .. (variable_arg or "nil"))

        if variable_name and variable_arg then
            --variable_name = variable_name:gsub("^!", "")
            if variable_name == "TX" then
                if not variable_arg:match("^%d$") then
                    -- check if it was a regex pattern (stripped of / delimiters)
                    if variable_arg:match("[%.%*%+%?%[%]]") then
                        -- preserve as regex pattern for TX variable lookup
                        variable_name = "TX_RX"
                    else
                        variable_arg = "1"
                    end
                end
            end

            -- check if variable_arg starts and end with a /
            if string.find(variable_arg, "^/") and string.find(variable_arg, "/$") then
                variable_arg = variable_arg:gsub("^/", ""):gsub("/$", "")
            end

            -- if the first character of variable_name is a !
            -- then use a rule control
            if string.find(variable_name, "^!") then
                -- check first if variable_name is not !REQUEST_COOKIES and variable_arg is not /__utm/
                -- this way to globally remove false positives, really doesn't make any sense.
                -- the main reason is that, it is not documented anywhere in the CRS documentation
                -- and we don't even know anymot why it is there...
                if variable_name ~= "!REQUEST_COOKIES" and variable_arg ~= "/__utm/" then
                    local new_variable_name = variable_name:gsub("^!", "")
                    table.insert(rule_control, {
                        remove_variable_rx = {
                            name = seclang.__get_variable_name(new_variable_name),
                            rx = variable_arg
                        }
                    })
                end
            elseif string.find(variable_name, "^&") then
                local new_variable_name = variable_name:gsub("^&", "")
                local vname = seclang.__get_variable_name(new_variable_name)
                if vname and variable_arg then
                    table.insert(variable_list, vname .. ":" .. variable_arg)
                elseif vname then
                    table.insert(variable_list, vname)
                end
            else
                -- ModSecurity XML:<xpath> variables. We don't run a real XPath
                -- engine; we recognise the two patterns CRS rules use in
                -- practice — `/*` (every element value) and `//@*` (every
                -- attribute value) — and map them to the flattened
                -- request.body.xml.* namespace the body parser produces.
                -- Anything else under XML falls back to element values as a
                -- best-effort approximation.
                if variable_name == "XML" then
                    if variable_arg == "//@*" then
                        table.insert(variable_list, "request.body.xml.attr.value")
                    else
                        table.insert(variable_list, "request.body.xml.value")
                    end
                else
                    local vname = seclang.__get_variable_name(variable_name)
                    if vname then
                        table.insert(variable_list,vname..":"..variable_arg)
                    end
                end
            end
        elseif variable_name and not variable_arg then
            if variable_name == "ARGS" then args_found = true end
            if variable_name == "ARGS_NAMES" then args_name_found = true end
            if variable_name == "REQUEST_COOKIES" then cookie_found = true end
            if variable_name == "REQUEST_COOKIES_NAMES" then cookie_name_found = true end

            local vname = seclang.__get_variable_name(variable_name)
            if vname then
                table.insert(variable_list, vname)
            end
        end
    end

    if args_found and args_name_found then
        -- remove request.args_names from variable_list
        for k,v in pairs(variable_list) do
            if v == "request.args_names" then
                table.remove(variable_list, k)
            end
        end
    end

    if cookie_found and cookie_name_found then
        -- remove request.cookies_names from variable_list
        for k,v in pairs(variable_list) do
            if v == "request.cookies_names" then
                table.remove(variable_list, k)
            end
        end
    end

    -- sort variables in order to have always the following in the same key
    -- 1 = request.arg.value
    -- 2 = request.arg.name
    -- 3 = request.path_with_query
    -- ... all others
    local ordered_variable_list = {}
    local order_start_with = 4
    for k,v in pairs(variable_list) do
        if v == "request.arg.value" then
            ordered_variable_list[1] = v
        elseif v == "request.arg.name" then
            ordered_variable_list[2] = v
        elseif v == "request.path_with_query" then
            ordered_variable_list[3] = v
        else
            ordered_variable_list[order_start_with] = v
            order_start_with = order_start_with + 1
        end
    end

    -- remove nil values from ordered_variable_list
    local i = 1
    while i <= #ordered_variable_list do
        if ordered_variable_list[i] == nil then
            table.remove(ordered_variable_list, i)
        else
            i = i + 1
        end
    end

    return ordered_variable_list,rule_control
    --return variable_list,rule_control
end

function seclang.__operator(op_line)
    --print("op_line: " .. op_line)

    if op_line == "@detectSQLi" then
        return "libinjection_sqli", ""    
    end

    if op_line == "@validateUrlEncoding" then
        return "validateUrlEncoding", ""
    end

    if op_line == "@validateUtf8Encoding" then
        return "validateUtf8Encoding", ""
    end

    if op_line == "@validateByteRange" then
        return "validateByteRange", ""
    end

    if op_line == "@detectXSS" then
        return "libinjection_xss", ""
    end

    local op,op_args = op_line:match("^(!?@[a-zA-Z]+) (.+)$")
    local negate = false
    if string.find(op, "!") then
        negate = true
    end

    op = op:gsub("^!", "")

    local op_translated = nil

    if op == "@rx" then
        op_translated = "rx"
    elseif op == "@pmFromFile" then
        op_translated = "pmFromFile"
    elseif op == "@pm" then
        op_translated = "pm"
    elseif op == "@streq" then
        op_translated = "eq"
    elseif op == "@eq" then
        op_translated = "eq"
    elseif op == "@ipMatch" then
        op_translated = "ipMatch"
    elseif op == "@within" then
        op_translated = "within"
    elseif op == "@beginsWith" then
        op_translated = "beginsWith"
    elseif op == "@endsWith" then
        op_translated = "endsWith"
    elseif op == "@contains" then
        op_translated = "contains"
    elseif op == "@gt" then
        op_translated = "gt"
    elseif op == "@lt" then
        op_translated = "lt"
    elseif op == "@ge" then
        op_translated = "ge"
    elseif op == "@le" then
        op_translated = "le"
    elseif op == "@validateByteRange" then
        op_translated = "validateByteRange"
    else
        print("----------> Unknown operator: " .. op)
        return
    end

    -- macro expansion translate on op_args
    if op_args:match("%%%{[tT][xX]%.%d+%}") then
        op_args = op_args:gsub("[tT][xX]%.", "group:")
    end

    if negate then
        return "!"..op_translated, op_args
    else
        return op_translated, op_args
    end
end

function seclang.__is_chained(raw_rule)
    if string.find(raw_rule, ",chain") or string.find(raw_rule, "chain,") or string.find(raw_rule, 'chain"') then
        return true
    else
        return false
    end
end

function seclang.__get_rule_id(actions)
    local id = actions:match("id:(%d+)")
    if id then
        return tonumber(id)
    else
        return nil
    end
end

function seclang.__get_tfunc(actions)
    local tfuncs = {}
    local t_none_found = false

    for tfunc_raw in actions:gmatch("t:([^,]+)") do
        if tfunc_raw ~= "none" then
            table.insert(tfuncs, tfunc_raw)
        else
            t_none_found = true
        end
    end

    -- add urlDecodeUni as default only when t:none was NOT specified
    -- ModSecurity resets all transformations on t:none, so we respect that
    if not t_none_found then
        local urldecode_found = false
        for k,v in pairs(tfuncs) do
            if v == "urlDecode" or v == "urlDecodeUni" then
                urldecode_found = true
            end
        end
        if not urldecode_found then
            table.insert(tfuncs, 1, "urlDecodeUni")
        end
    end

    return tfuncs
end

function seclang.__get_phase(actions)
    local phase = actions:match("phase:(%d+)")
    if phase then
        if phase == "1" or phase == "2" then
            return "access"
        end
        if phase == "3" then
            return "header_filter"
        end
        if phase == "4" then
            return "body_filter"
        end
    else
        return "access"
    end
end

function seclang.__get_message(actions)
    local msg = actions:match("msg:'([^']+)'")
    if msg then
        return msg
    else
        return ""
    end
end

function seclang.__get_logdata(actions)
    local logdata = actions:match("logdata:'([^']+)'")
    if logdata then
        return logdata
    else
        return ""
    end
end

function seclang.__get_paranoia_level(actions)
    local level = actions:match("tag:'paranoia%-level/(%d)'")
    if level then
        return level
    else
        return tostring(1)
    end
end

function seclang.__get_tags(actions)
    local tags = {}
    for tag in actions:gmatch("tag:'([^']+)'") do
        table.insert(tags, tag)
    end
    return tags
end

function seclang.__get_action(actions)
    local action = {["setvar"] = {}}
    if actions:match(",block") or actions:match("block,") then
        action["fixed_response"] = {
            status_code = 403,
            headers = {
                ["content-type"] = "text/plain",
                ["cache-control"] = "max-age=0, private, no-store, no-cache, must-revalidate"
            },
            body = "Forbidden\r\n"
        }
    end

    -- setvar:'tx.rfi_parameter_%{MATCHED_VAR_NAME}=.%{tx.1}'
    local setvars = string.gmatch(actions, "setvar:'tx%.([^=]+)=([^']+)'")
    while true do
        local vvar,vvalue = setvars()
        if vvalue then
            table.insert(action["setvar"], {var_name=vvar, var_value=vvalue})
        else
            break
        end
    end

    return action
end

function seclang.__parse_rule(rule_raw, chained, filter_by_id)
    --print("----------> Parse rule -> chained:" .. tostring(chained))

    -- if skipAfter then skip rule
    if rule_raw:match("skipAfter:") then
        return
    end

    local id = "0"
    --print("----- rule -----" .. tostring(chained))

    local variables,operators,actions = rule_raw:match('^SecRule%s+([^%s]+)%s+"(.+)"%s+"(.+)"$')
    --print("variables: "..variables)
    --print("operators: "..operators)
    --print("actions: "..actions)

    if not actions then
        -- defensive: malformed SecRule (or a syntax variant we don't yet handle).
        -- Better to lose one rule than to abort init_worker for the whole plugin.
        print("----------> WARN: SecRule skipped, unparsable: " .. tostring(rule_raw):sub(1, 120))
        return
    end

    id = seclang.__get_rule_id(actions)
    if not id and not chained then
        print("----------> ERROR: Rule without id")
        return
    end


    if not id and chained then
        if not filter_by_id then
            --print("set rule last id to " .. rule_last_id)
            id = rule_last_id
        end
    end

    id = tostring(id)


    if filter_by_id then
        if id then
            if id ~= filter_by_id then
                --print("Skip rule: " .. id .. " (filter by id)")
                return
            end
        end
    end

    local rule = {
        control = {},
        variables = {},
        operator = "",
        operator_args = ""
    }

    rule.operator, rule.operator_args = seclang.__operator(operators)

    -- convert &variable count workarounds to isSet/!isSet
    if variables and string.find(variables, "^&") then
        if rule.operator == "!eq" and rule.operator_args == "0" then
            rule.operator = "isSet"
            rule.operator_args = ""
        elseif rule.operator == "eq" and rule.operator_args == "0" then
            rule.operator = "!isSet"
            rule.operator_args = ""
        end
    end

    if variables and string.find(variables, "|") then
        string.gsub(variables, "([^|]+)", function (v)
            table.insert(rule.variables, v)
        end)
    else
        table.insert(rule.variables, variables)
    end

    if not chained then
        rules[id] = {
            id = tostring(id),
            conditions = {},
            phase = seclang.__get_phase(actions),
            tags = seclang.__get_tags(actions),
            action = seclang.__get_action(actions),
            message = seclang.__get_message(actions),
            logdata = seclang.__get_logdata(actions),
            paranoia_level = "1"
        }
    end

    rule.variables,rule.control = seclang.__variables_to_conditions(rule.variables)

    local transformation_functions = seclang.__get_tfunc(actions)

    local is_multi_match = false
    if rule_raw:match("multiMatch") then
        is_multi_match = true
    end

    table.insert(rules[id]["conditions"], {
        variables = rule.variables,
        op = rule.operator,
        value = rule.operator_args,
        transform = transformation_functions,
        multi_match = is_multi_match
    })

    -- set paranoia level condition
    if not chained then
        local pl = seclang.__get_paranoia_level(actions)
        --[[table.insert(rules[id]["conditions"], {
            variables = {"var:paranoia_level"},
            op = "ge",
            value = pl
        })]]--

        rules[id]["paranoia_level"] = pl
    end

    if #rule.control > 0 then
        if not rules[id]["rule_control"] then
            rules[id]["rule_control"] = {}
        end
        for k,v in pairs(rule.control) do
            table.insert(rules[id]["rule_control"], v)
        end
    end

    rule_last_id = id
    --print("KongArmour Parsed Rule: " .. id)
    --print("Rule:")
    --print(inspect(rule))

end

return seclang