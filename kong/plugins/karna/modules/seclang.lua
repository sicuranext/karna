local seclang = {}
local rules = {}
local rule_last_id = 0
local rule_is_chained = false

seclang.crs_path = os.getenv("KARNA_CRS_PATH") or "/opt/coreruleset/rules/"
if not seclang.crs_path:match("/$") then
    seclang.crs_path = seclang.crs_path .. "/"
end

-- Parse a SecLang blob into a fresh `{id = rule}` table without
-- mutating the long-lived module-level `rules` cache (which holds the
-- merged CRS + coreruleset_fix rule pack populated at init_worker).
-- Used by handler.lua at access phase to load CRS exclusion plugins
-- and `custom_secrules` per-instance — those need to be evaluated as
-- a *separate* rule list and must not leak into the init-time pack.
function seclang.parse_isolated(raw_rules, filter_by_id)
    local backup = {}
    for k, v in pairs(rules) do backup[k] = v end
    for k in pairs(rules) do rules[k] = nil end

    seclang.parse(raw_rules, filter_by_id)

    local result = {}
    for k, v in pairs(rules) do result[k] = v end

    for k in pairs(rules) do rules[k] = nil end
    for k, v in pairs(backup) do rules[k] = v end

    return result
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
            -- Load every rule regardless of declared paranoia level. The
            -- runtime PL gate in `ka_engine.loop_rules` skips rules whose
            -- `rule.paranoia_level` exceeds `plugin_conf.paranoia_level`
            -- (default 1), so vanilla deployments still evaluate only
            -- PL1 — but operators can opt into PL2/3/4 simply by raising
            -- the config knob, without an init_worker reload. Skipping
            -- PL2+ here would render the runtime gate inert.
            seclang.__parse_rule(rule, rule_is_chained, filter_by_id)
            rule_is_chained = seclang.__is_chained(rule)
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
                    --print("found conf file: " .. filename)
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

-- Scan `<plugin_dir>/*.conf` (typically the `plugins/` subdir of a
-- CRS exclusion plugin like wordpress-rule-exclusions-plugin) and
-- return a `{ filename = raw_conf_content }` map ready to feed into
-- `seclang.parse`. Missing dirs return an empty map — by design,
-- the operator may declare a plugin name that isn't on disk yet
-- (CI bootstrap, optional installs), and we'd rather load no
-- rules than crash the access phase.
function seclang.collect_plugin_conf_files(plugin_dir)
    if not plugin_dir or plugin_dir == "" then return {} end
    if not plugin_dir:match("/$") then plugin_dir = plugin_dir .. "/" end

    local files = {}
    -- io.popen here is fork+exec — acceptable because this only runs
    -- on the first request after a plugin-config change (cached in the
    -- handler-side LRU thereafter), not on every request.
    local pfile = io.popen('ls -a "' .. plugin_dir .. '" 2>/dev/null')
    if not pfile then return files end

    for filename in pfile:lines() do
        if filename:match("%.conf$") then
            local fh = io.open(plugin_dir .. filename, "r")
            if fh then
                files[filename] = fh:read("*all")
                fh:close()
            end
        end
    end
    pfile:close()

    return files
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
        ["REQUEST_BODY_LENGTH"]     = "request.body.length",
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
        --print("----------> Unknown variable: " .. varname)
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
                if variable_arg:match("^%d$") then
                    -- TX:0 / TX:1 / ... — numeric capture-group references,
                    -- handled elsewhere via group:N resolution. Leave alone.
                else
                    -- TX:<name> — named transaction variable. Emit as the
                    -- Karna-side rule variable `tx:<lowercase_name>`. The
                    -- engine resolves these from `kong.ctx.plugin.tx_variables`,
                    -- populated either by setvar actions during rule
                    -- evaluation OR by handler:access from plugin_conf
                    -- (CRS-setup-style config knobs — see schema.lua).
                    if variable_arg:match("[%.%*%+%?%[%]]") then
                        -- TX:/regex/ pattern — preserve for TX_RX handling
                        variable_name = "TX_RX"
                    else
                        table.insert(variable_list, "tx:" .. variable_arg:lower())
                        goto continue_outer
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
                -- ModSec's `&VAR` operator: evaluate to the COUNT of values
                -- VAR resolves to. Used in CRS for "header missing" / "header
                -- present" patterns (`&X @eq 0` / `&X @gt 0`). We surface
                -- this to the engine as a `count:<name>` prefix; the engine
                -- resolver returns a numeric scalar that the numeric ops
                -- (@eq/@gt/@lt/@ge/@le) compare against.
                local new_variable_name = variable_name:gsub("^&", "")
                local vname = seclang.__get_variable_name(new_variable_name)
                if vname and variable_arg then
                    table.insert(variable_list, "count:" .. vname .. ":" .. variable_arg)
                elseif vname then
                    table.insert(variable_list, "count:" .. vname)
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
                        -- `/*` (and any other xpath): scan element values AND
                        -- attribute values. Attribute values are a real
                        -- injection surface — scanning only element text let an
                        -- attacker hide SQLi/XSS in an attribute (`<x q="..."/>`)
                        -- and skip inspection (WAF bypass). Element/attribute
                        -- NAMES are intentionally NOT added: folding names into
                        -- the scan is the 944120-class false-positive vector.
                        table.insert(variable_list, "request.body.xml.value")
                        table.insert(variable_list, "request.body.xml.attr.value")
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

            -- FILES_NAMES is the multipart part's `name=` field per
            -- ModSec semantics, NOT the `filename=` value. Karna kept
            -- the historic `.filename` mapping for a long time because
            -- the semantically-correct `.name` mapping triggered FPs
            -- in some 920120 negative tests. Approach B:
            -- emit BOTH targets when FILES_NAMES is referenced. The
            -- 920120 rule's `!@rx` pattern then evaluates against
            -- every multipart name AND every multipart filename — a
            -- form-data bypass attack via either is caught. Additive
            -- (no removal of the historic .filename mapping) so any
            -- caller that already used FILES_NAMES expecting filenames
            -- continues to work.
            if variable_name == "FILES_NAMES" then
                table.insert(variable_list, "request.body.multipart.name")
                table.insert(variable_list, "request.body.multipart.filename")
            else
                local vname = seclang.__get_variable_name(variable_name)
                if vname then
                    table.insert(variable_list, vname)
                end
            end
        end
        ::continue_outer::
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

    if op_line == "@unconditionalMatch" then
        return "unconditionalMatch", ""
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
    elseif op == "@validateUrlEncoding" then
        -- Engine implements this operator (run_operator dispatch), but the
        -- SecLang map was missing it, so any CRS rule using it (920220 et al.,
        -- in the default-off 920 family) loaded with a nil operator and silently
        -- never matched. Wire it through so enabling 920 actually enforces it.
        op_translated = "validateUrlEncoding"
    elseif op == "@validateUtf8Encoding" then
        -- Same as above for 920250 (UTF-8 validity). Engine implements it; the
        -- map was missing it.
        op_translated = "validateUtf8Encoding"
    else
        --print("----------> Unknown operator: " .. op)
        return
    end

    -- macro expansion translate on op_args
    if op_args:match("%%%{[tT][xX]%.%d+%}") then
        op_args = op_args:gsub("[tT][xX]%.", "group:")
    end

    -- Canonical Karna shape: return `(op_base, args, negated)`.
    -- ModSecurity's `@!op` prefix is the input format; on output we
    -- always emit the base op + a separate `negated` boolean so the
    -- match engine doesn't have to think about two notations.
    -- (The engine's normalization layer still accepts legacy `!op`
    -- for hand-written JSON rules — see __match_rule_conditions.)
    return op_translated, op_args, negate
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

    for tfunc_raw in actions:gmatch("t:([^,]+)") do
        if tfunc_raw ~= "none" then
            table.insert(tfuncs, tfunc_raw)
        end
        -- `t:none` is a parser-only marker in ModSec — it resets any
        -- inherited transformation chain, which only matters if
        -- SecDefaultAction had set defaults. Karna doesn't honour
        -- SecDefaultAction, so an explicit transform list is the
        -- complete transform list. We don't add `t:none` itself to
        -- the runtime list and we don't add an implicit urlDecodeUni.
        --
        -- Previously Karna inserted `urlDecodeUni` as a default when
        -- the rule omitted any `t:` directive. That diverged from
        -- ModSec semantics (no implicit transforms) and produced
        -- spurious FPs in chained rules whose second condition reads
        -- a TX variable that legitimately contains `+` — e.g. 920420
        -- cond2 (`t:lowercase` only) where `+` in `application/soap+xml`
        -- got rewritten to space by the implicit urlDecodeUni, breaking
        -- the `@within` allow-list check.
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
        -- status_code only: body and headers are deliberately NOT baked
        -- into the parsed rule, so the serve path (handler.lua) fills
        -- them at block time from default_block_response_body/_headers
        -- (plugin config) or the built-in "Forbidden\r\n" fallback. A
        -- baked body here would shadow the operator's default block page
        -- for every CRS rule — the main use case.
        action["fixed_response"] = {
            status_code = 403
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

-- Resolve a `ctl:*` target spec (`ARGS:foo`, `REQUEST_HEADERS:Referer`,
-- `ARGS`, …) into the Karna-side variable key the engine actually
-- populates in `values`. CRS exclusion plugins use the ModSec variable
-- naming on the right side of the semicolon; Karna's per-request target
-- removal compares against keys like `request.arg.value:foo`, so we
-- have to bridge here.
function seclang.__parse_ctl_target(target_str)
    if not target_str or target_str == "" then return nil end
    local vname, varg = target_str:match("^([^:]+):(.+)$")
    if vname and varg then
        local mapped = seclang.__get_variable_name(vname)
        if not mapped then return nil end
        if vname == "REQUEST_HEADERS" or vname == "REQUEST_HEADERS_NAMES" then
            varg = varg:lower()
        end
        return mapped .. ":" .. varg
    end
    return seclang.__get_variable_name(target_str)
end

-- Parse `ctl:*` directives from a SecRule's action string. These are
-- per-request rule controls — when this rule's match condition fires,
-- handler.lua applies them to `kong.ctx.plugin.rule_controls`,
-- affecting how *subsequent* rules in the same request evaluate.
-- Used heavily by CRS exclusion plugins (wordpress, drupal, nextcloud,
-- …) to whitelist app-specific param names / disable rules on known
-- endpoints. Supported directives:
--   ctl:ruleRemoveById=<id|range>            → drop the rule entirely
--   ctl:ruleRemoveTargetById=<id>;<target>   → drop one target from <id>
--   ctl:ruleRemoveTargetByTag=<tag>;<target> → drop one target from rules tagged <tag>
--   ctl:ruleEngine=Off                       → bypass WAF for this request
-- Unrecognised directives are ignored (forward-compat with future CRS
-- additions; matches our defensive parsing posture for malformed input).
function seclang.__get_rule_controls(actions)
    local controls = {}
    if not actions or actions == "" then return controls end

    -- ctl:ruleEngine=Off — must check before generic ctl: gmatch so
    -- the casing is preserved and we can match the literal "Off".
    if actions:match("ctl:ruleEngine%s*=%s*Off") then
        table.insert(controls, { engine_off = true })
    end

    for directive_arg in actions:gmatch("ctl:([^,]+)") do
        local name, rhs = directive_arg:match("^([%w_]+)%s*=%s*(.+)$")
        if name and rhs then
            if name == "ruleRemoveById" then
                -- rhs is either "920100" or "920100-920199" — handler.lua
                -- does the range expansion at request time.
                table.insert(controls, { remove_rule = { rule_id = rhs } })
            elseif name == "ruleRemoveTargetById" then
                local id_part, target_part = rhs:match("^([%d%-]+);(.+)$")
                if id_part and target_part then
                    local mapped = seclang.__parse_ctl_target(target_part)
                    if mapped then
                        table.insert(controls, {
                            remove_target_from_rule_by_id = {
                                rule_id = id_part,
                                target = mapped,
                            }
                        })
                    end
                end
            elseif name == "ruleRemoveTargetByTag" then
                local tag_part, target_part = rhs:match("^([^;]+);(.+)$")
                if tag_part and target_part then
                    local mapped = seclang.__parse_ctl_target(target_part)
                    if mapped then
                        table.insert(controls, {
                            remove_target_rule_by_tag = {
                                tag = tag_part,
                                name = mapped,
                            }
                        })
                    end
                end
            end
        end
    end

    return controls
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
        --print("----------> ERROR: Rule without id")
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
        operator_args = "",
        operator_negated = false,
    }

    rule.operator, rule.operator_args, rule.operator_negated = seclang.__operator(operators)

    -- NOTE: a previous version of this code rewrote `&VAR @eq 0` /
    -- `&VAR !@eq 0` into `isSet` with a flipped `negated` flag, on
    -- the assumption that "count == 0" was equivalent to "variable
    -- not set". That was wrong: Karna's `count:` virtual variable
    -- resolves to the literal string `"0"` when the underlying
    -- variable is absent, and `isSet` matches `"0"` as "value set"
    -- (truthy in Lua), so the rewrite caused the rule to fire on
    -- *every* request — a benign-traffic 50 % spurious-block rate
    -- under load, masked for months by the cache-leak bug that
    -- emptied the values map before the rule could evaluate.
    -- The numeric op (`@eq 0`, `@gt 0`) already works correctly
    -- against the count: virtual variable in the engine, so we
    -- leave it alone.

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
        negated = rule.operator_negated,
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

    -- Per-request rule controls declared via `ctl:*` action directives
    -- (CRS exclusion plugins). Only parsed on the head rule of a chain
    -- — for chained children we'd see the same actions string from
    -- the head, which would double-register. The handler will apply
    -- these to `kong.ctx.plugin.rule_controls` when this rule fires.
    if not chained then
        local ctl_controls = seclang.__get_rule_controls(actions)
        if #ctl_controls > 0 then
            if not rules[id]["rule_control"] then
                rules[id]["rule_control"] = {}
            end
            for _, v in ipairs(ctl_controls) do
                table.insert(rules[id]["rule_control"], v)
            end
        end
    end

    rule_last_id = id

end

return seclang