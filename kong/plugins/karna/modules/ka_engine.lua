--[[
    Karna - Engine module
]]--

local _M = {}

_M._VERSION = "0.1"
_M._NAME = "Karna"
_M._ka_dfiles = {}

local ngx                               = ngx
local kong                              = kong
local get_phase                         = ngx.get_phase
local ngx_re_match                      = ngx.re.match
local ngx_re_gmatch                     = ngx.re.gmatch
local ngx_req_get_body_file             = ngx.req.get_body_file
local ngx_decode_base64                 = ngx.decode_base64

local string_match                      = string.match
local string_gmatch                     = string.gmatch
local table_insert                      = table.insert
local table_remove                      = table.remove
local string_gsub                       = string.gsub
local string_char                       = string.char
local string_lower                      = string.lower
local string_len                        = string.len
local string_find                       = string.find

--local request_get_query                 = kong.request.get_query
local request_get_scheme                = kong.request.get_scheme
local request_get_host                  = kong.request.get_host
local request_get_port                  = kong.request.get_port
local request_get_forwarded_scheme      = kong.request.get_forwarded_scheme
local request_get_forwarded_host        = kong.request.get_forwarded_host
local request_get_forwarded_port        = kong.request.get_forwarded_port
local request_get_forwarded_path        = kong.request.get_forwarded_path
local request_get_forwarded_prefix      = kong.request.get_forwarded_prefix
local request_get_http_version          = kong.request.get_http_version
local request_get_method                = kong.request.get_method
local request_get_path                  = kong.request.get_path
local request_get_raw_path              = kong.request.get_raw_path
local request_get_path_with_query       = kong.request.get_path_with_query
local request_get_raw_query             = kong.request.get_raw_query
local request_get_headers               = kong.request.get_headers
local request_get_header                = kong.request.get_header
local request_get_raw_body              = kong.request.get_raw_body

local response_get_headers              = kong.service.response.get_headers
local response_get_status               = kong.service.response.get_status
local response_exit                     = kong.response.exit

local body_parser                       = require "kong.plugins.karna.ka_body_parser"
local utils                             = require "kong.plugins.karna.ka_utils"
local seclang                           = require "kong.plugins.karna.ka_seclang"
local libinjection                      = require "kong.plugins.karna.libinjection"

local ka_rules_crs_fix                  = require "kong.plugins.karna.ka_rules_crs_fix"

-- module-level debug flag for hot-path gating (set in loop_rules from plugin_conf.private_debug)
local private_debug_enabled = false

local cjson                             = require "cjson"
local cjson_safe                        = require "cjson.safe"
local ka_mcp                            = require "kong.plugins.karna.ka_mcp"
--local httpc                           = require "resty.http"
--local ipmatcher                       = require "resty.ipmatcher"
local b64                               = require "ngx.base64"
local md5                               = ngx.md5

--local debug       = function(i) return end
--local inspect     = function(i) return end
local debug     = kong.log.debug
local inspect   = kong.log.inspect

_M.load_rules = function(self)
    local rules = {}
    local rcontrol_rules = {}
    local dfiles = {}

    --[=[

        {
            "id": "local_1",
            "phase": "access",
            "conditions": [{"op": "beginsWith", "transform": [], "value": "/pippo", "variables": ["request.path_with_query"]}],
            "action": {"fixed_response": {"body": "Forbidden", "headers": {"cache-control":"max-age=0, private, no-store, no-cache, must-revalidate", "content-type":"text/plain"}, "status_code": 403}},
            "log": true,
            "message": "Test local service rule",
            "tags": ["local", "test"]
        }

        {
            "id": "local_2",
            "phase": "access",
            "conditions": [{"op": "beginsWith", "transform": [], "value": "/", "variables": ["request.path_with_query"]}],
            "action": {},
            "log": false,
            "rule_control": [
                {
                    "remove_variable_from_rule_conditions": {
                        "rule_id": "local_1",
                        "variable_name": "request.path_with_query"
                    }
                }
            ]
        }

        rules["1234"] = {
            id = "1234",
            phase = "access",
            conditions = {
            {
                multi_match = false,
                op = "rx",
                transform = { "urlDecodeUni" },
                value = "['\"`]+.*['\"`;&|]+",
                variables = { "request.arg.value" }
            },
            {
                multi_match = false,
                op = "ge",
                value = "1",
                variables = { "var:paranoia_level" }
            }
            },
            action = {
                fix_matched_parts = {
                    remove_chars_pattern = "[\"';&|`]*"
                }
            },
            logdata = "",
            message = "",
            rule_control = {},
            tags = {}
        }
        ]=]--

        --[[
        rules["1235"] = {
            id = "1235",
            phase = "access",
            conditions = {
            {
                multi_match = false,
                op = "rx",
                transform = { "urlDecodeUni" },
                value = "[$][^(]*[(].+[)]",
                variables = { "request.arg.value", "request.raw_path", "request.header.value" }
            },
            {
                multi_match = false,
                op = "ge",
                value = "1",
                variables = { "var:paranoia_level" }
            }
            },
            action = {
                fix_matched_parts = {
                    remove_chars_pattern = "[$()]"
                }
            },
            logdata = "",
            message = "",
            rule_control = {},
            tags = {}
        }
        ]]--

        --[[
        rules["1239"] = {
            id = "1239",
            phase = "access",
            conditions = {
                {
                    multi_match = false,
                    op = "beginsWith",
                    transform = { "none" },
                    value = "/",
                    variables = { "request.raw_path" }
                }
            },
            rule_control = {
                {
                    change_rule_action = {
                        rule_id = "933160",
                        action = {
                            fix_matched_parts = {
                                remove_chars_pattern = "[\"';|`()]"
                            }
                        }
                    }
                }
            }
        }
    ]]--

    -- Loading CRS-fix rules (rule controls that patch known false-positive-
    -- prone CRS rules in production deployments).
    for _,rule in pairs(ka_rules_crs_fix.global_fps) do

        -- Sort conditions by estimated cost (simple first)
        if rule.conditions then
            table.sort(rule.conditions, function(a, b)
                -- Put simple equality checks before regex
                --if a.op == "eq" and b.op ~= "eq" then return true end
                --if a.op ~= "eq" and b.op == "eq" then return false end

                -- Put "isSet" checks before matching operations
                if a.op == "isSet" and b.op ~= "isSet" then return true end
                if a.op ~= "isSet" and b.op == "isSet" then return false end

                -- Default order
                return false
            end)
        end

        rules[#rules+1] = rule
    end

    -- Loading CRS rules
    local parsed_rules = {}
    local crs_files_contents = seclang.collect_crs_conf_files()
    table.sort(crs_files_contents)
    for filename,content in pairs(crs_files_contents) do
        parsed_rules = seclang.parse(content)
        kong.log.debug("Parsed " .. tostring(#parsed_rules) .. " rules from CRS file: " .. filename)
        for rule_id,rule in pairs(parsed_rules) do
            kong.log.debug("  -> Rule ID: " .. tostring(rule_id) .. " / Message: " .. tostring(rule.message))
        end
    end

    local rules_count = 0
    table.sort(parsed_rules)
    for rule_id,rule in pairs(parsed_rules) do
        rules_count = rules_count + 1
        rule.log = true

        -- Sort conditions by estimated cost (simple first)
        if rule.conditions then
            table.sort(rule.conditions, function(a, b)
                -- Put simple equality checks before regex
                --if a.op == "eq" and b.op ~= "eq" then return true end
                --if a.op ~= "eq" and b.op == "eq" then return false end

                -- Put "isSet" checks before matching operations
                if a.op == "isSet" and b.op ~= "isSet" then return true end
                if a.op ~= "isSet" and b.op == "isSet" then return false end

                -- Default order
                return false
            end)
        end

        rules[#rules+1] = rule
    end
    debug("Rules Count: " .. tostring(rules_count))


    --[[local rules_total_count = 0
    for rule_id,rule in pairs(rules) do
        rules_total_count = rules_total_count + 1
    end
    debug("Rules Total Count: " .. tostring(rules_total_count))]]--


    -- Fix CRS Rules
    --rules[#rules+1] = ka_rules_crs_fix.rule_crs_fix_4_0

    -- temp disabled
    rules = self:__evaluate_rule_control(rules,rules)

    -- Load CRS dfiles
    table.sort(parsed_rules) -- check if this is needed / if a metadata is needed
    for _,rule in pairs(rules) do
        if rule.conditions then
            for _,condition in pairs(rule.conditions) do
                if condition.op == "pmFromFile" then
                    local dfile = seclang.collect_data_file(seclang.crs_path .. condition.value)
                    dfiles[condition.value] = dfile
                end
            end
        end
    end

    -- Store dfiles in module for access during rule evaluation
    _M._ka_dfiles = dfiles

    debug("+++++++++> Sending " .. tostring(#rules) .. " rules")

    return rules, rcontrol_rules, dfiles
end

--[[
  1. Cache rule inspection tables more aggressively:
    - The __set_rule_inspection_table function (lines 1982-2412) builds large inspection tables for each rule condition, but the caching mechanism is only used for certain variable
  types.
    - Extend the caching to cover all variable types for rule inspection.
  2. Reduce string pattern matching operations:
    - There are many string_match calls that could be optimized by pre-compiling patterns.
    - Consider using ngx.re.match with the "o" option to compile regex patterns once.
  3. Optimize transformation functions:
    - The __apply_transformation function (lines 2528-2799) contains many string replacements that are expensive.
    - Consider consolidating multiple string_gsub operations into single passes where possible.
  4. Implement early exit for rule evaluation:
    - Add a fast path to skip rules that won't match based on quick checks before going through the expensive matching process.
  5. Optimize rule conditions evaluation loop:
    - Reorder conditions to check the simplest/fastest conditions first.
    - Break early when a condition fails rather than processing all conditions.
  6. Use local variable caching:
    - Cache frequently accessed values to avoid table lookups and function calls.
    - For example, cache kong.ctx.plugin and other nested structures as local variables.
  7. Reduce table operations:
    - Each table_insert operation has overhead. Consider pre-allocating tables where possible.
    - Batch insert operations when possible.
  8. Implement lazy loading for data files:
    - Only load data files when needed instead of loading all at once.
  9. Use LuaJIT's table features effectively:
    - LuaJIT's JIT compiler works best with certain table usage patterns.
    - Ensure tables have sequential integer keys where appropriate.
  10. Add profiling:
    - Add optional profiling points to identify the slowest parts of the function.
    - Consider measuring time spent in each part of the function to identify bottlenecks.

  The most critical areas appear to be the rule inspection table generation and the rule condition matching logic, where significant performance gains could be achieved by restructuring
  these operations.

]]--
_M.loop_rules_old = function(self, plugin_conf, raw_rules, phase, local_rules, is_dev_env_enabled, filter_rule_id, ka_dfiles, rules_control_already_applied)
    --kong.log.inspect(rules)
    debug("Looping rules for phase: " .. phase .. " / rule count: " .. tostring(#raw_rules) .. " / nginx worker number: " .. tostring(ngx.worker.id()))

    --[[local rules_control_applied = {}

    if not rules_control_already_applied then
        local rules = utils:copy_rule_table(raw_rules, plugin_conf.paranoia_level)

        rules_control_applied = self:__evaluate_rule_control(rules, local_rules, plugin_conf)

        debug("Rules count after rule control evaluation: " .. tostring(#rules_control_applied))
        debug("Rules saved in cache: " .. tostring(#rules))
    else
        rules_control_applied = rules_control_already_applied
    end]]--

    local rules_control_applied = raw_rules

    for _,rule in pairs(rules_control_applied) do
        if rule.phase == phase then
            --inspect(rule)

            -- check if rule is dependent by a plugin schema field
            if rule.plugin_schema_field_name then
                if rule.plugin_schema_field_value ~= tostring(plugin_conf[rule.plugin_schema_field_name]) then
                    goto continue
                end
            end

            -- check if rule is configured to be executed only if a request body is present
            if rule.if_body then
                if not kong.ctx.plugin.request_has_body then
                    goto continue
                end
            end

            --debug("Checking rule " .. tostring(rule.id) .. " for phase " .. phase)

            if not rule.paranoia_level then
                rule.paranoia_level = 1
            end

            if tonumber(rule.paranoia_level) > tonumber(plugin_conf.paranoia_level) then
                goto continue
            end

            kong.ctx.plugin.rule_inspection_table = {}
            kong.ctx.plugin.rule_matched_parts = {}

            if filter_rule_id and filter_rule_id ~= rule.id then
                debug("Skipping rule " .. tostring(rule.id) .. " because it does not match the filter rule id " .. tostring(filter_rule_id))
            else
                local rule_matched = false
                local matched_parts = {}

                rule_matched, matched_parts = self:__match_rule_conditions(rule, plugin_conf, ka_dfiles)

                if rule_matched then
                    --inspect(rule)

                    table.insert(
                        kong.ctx.plugin.ka_matched_rules,
                        {
                            rule = rule,
                            part = matched_parts
                        }
                    )

                    -- if log in rule and rule.log is true
                    if rule.log then
                        if plugin_conf.auditlog_error_log_on_match then
                            kong.log.err("Rule " .. tostring(rule.id) .. " \"".. tostring(rule.message) .."\" matched on phase ".. phase ..". Matched parts: " .. cjson.encode(matched_parts))
                        end
                    end

                    if rule.action then

                        if rule.action.fixed_response then
                            if plugin_conf.engine_blocking_mode then
                                local response_body = rule.action.fixed_response.body

                                -- replace variables in response body
                                response_body = self:replace_variable_in_string(response_body)

                                if is_dev_env_enabled then
                                    response_body = "Rule:" .. tostring(rule.id) .. " / Matched parts:" .. cjson.encode(matched_parts)
                                end

                                local fixed_response_headers = {}

                                for k,v in pairs(rule.action.fixed_response.headers) do
                                    fixed_response_headers[k] = self:replace_variable_in_string(v)
                                end

                                if not fixed_response_headers then
                                    fixed_response_headers = {
                                        ["content-type"] = "text/plain",
                                        ["cache-control"] = "max-age=0, private, no-store, no-cache, must-revalidate"
                                    }
                                end

                                return kong.response.exit(
                                    rule.action.fixed_response.status_code,
                                    response_body,
                                    fixed_response_headers
                                )
                            end
                        end

                        if rule.action.fix_matched_parts then
                            self:__fix_matching_parts(rule, matched_parts)
                        end

                        if rule.action.set_log_fields then
                            for _,alf in pairs(rule.action.set_log_fields) do
                                if alf.name and alf.value then
                                    kong.log.err("Setting log field: " .. alf.name .. " with value: " .. alf.value)
                                    self:__set_log_field(alf.name, alf.value)
                                end
                            end
                        end

                        if rule.action.redis_incr_key then
                            if rule.action.redis_incr_key.key and rule.action.redis_incr_key.expire then
                                local key_name_resolved = self:replace_variable_in_string(rule.action.redis_incr_key.key)
                                debug("REDIS ->>> Key name resolved: " .. key_name_resolved)
                                if phase == "access" then
                                    utils:redis_incr_key(key_name_resolved, rule.action.redis_incr_key.expire)
                                else
                                    -- using ngx timer to increment key in a different phase
                                    local ok, err = ngx.timer.at(0, utils.redis_incr_key_async, utils, plugin_conf, key_name_resolved, rule.action.redis_incr_key.expire)
                                    if not ok then
                                        kong.log.err("Error incrementing redis key: " .. err)
                                    end
                                end
                            end
                        end

                        if rule.action.set_variable then
                            debug("set variable action found")
                            if rule.action.set_variable.name and rule.action.set_variable.value ~= nil then
                                if rule.action.set_variable.type then
                                    if rule.action.set_variable.type == "plugin" then
                                        debug("Setting plugin variable: " .. rule.action.set_variable.name .. " with value: " .. tostring(rule.action.set_variable.value))
                                        kong.ctx.plugin[rule.action.set_variable.name] = rule.action.set_variable.value
                                    elseif rule.action.set_variable.type == "shared" then
                                        debug("Setting shared variable: " .. rule.action.set_variable.name .. " with value: " .. tostring(rule.action.set_variable.value))
                                        kong.ctx.shared[rule.action.set_variable.name] = rule.action.set_variable.value
                                    end
                                end
                            end
                        end

                    end -- end if rule.action

                end -- end if rule_matched

            end -- end if filter_rule_id

            ::continue::

        end -- end if rule.phase

    end -- end for rules

    return rules_control_applied
end



_M.__get_values_request_body = function(try_b64)
    if get_phase() == "init_worker" then
        return {}, nil
    end

    -- cache lookup: avoid re-parsing the body on every condition that reads it
    local cache_key = try_b64 and "b64" or "raw"
    if kong.ctx.plugin then
        if not kong.ctx.plugin.body_values_cache then
            kong.ctx.plugin.body_values_cache = {}
        end
        if kong.ctx.plugin.body_values_cache[cache_key] ~= nil then
            return kong.ctx.plugin.body_values_cache[cache_key], nil
        end
    end

    local values = {}
    local result_values = values
    local result_err = nil

    local content_length_header = kong.request.get_header("content-length")
    if content_length_header and tonumber(content_length_header) > 0 then

        -- get request body
        local request_body = request_get_raw_body()

        -- if not request_body, but content-length is set, then try to use ngx.req.get_body_file
        -- ngx.req.get_body_file: Retrieves the file name for the in-file request body data. Returns nil if the request body has not been read or has been read into memory.
        if not request_body then
            local body_file = ngx_req_get_body_file()
            if body_file then
                debug("-> Reading request body from file")
                local file = io.open(body_file, "r")
                if file then
                    request_body = file:read("*a")
                    file:close()
                end
            end
        end

        -- parse request body
        if request_body and request_body ~= "" then
            -- get request body type
            local request_body_type = utils:request_body_parser_type()

            if request_body_type == "json" then
                local json_flattened, err = body_parser:json("request.body.json", request_body, try_b64)
                if json_flattened then
                    result_values = json_flattened
                else
                    result_values = nil
                    result_err = err
                end
            elseif request_body_type == "xml" then
                -- NB: legacy behavior — xml parsing result is not currently used as values
                body_parser:xml("request.body.xml", request_body)
            elseif request_body_type == "urlencoded" then
                local urlencoded_flattened = body_parser:urlencoded("request.body.urlencode", request_body, try_b64)
                if urlencoded_flattened then
                    result_values = urlencoded_flattened
                end
            elseif request_body_type == "multipart" then
                local multipart_flattened = body_parser:multipart("request.body.multipart", request_body, try_b64)
                if multipart_flattened then
                    -- convert array of tables to flat table
                    for _, entry in pairs(multipart_flattened) do
                        for k, v in pairs(entry) do
                            values[k] = v
                        end
                    end
                    result_values = values
                end
            end
        end
    end

    -- store in cache (including empty results, to avoid re-parsing on subsequent calls)
    if kong.ctx.plugin and result_values ~= nil then
        kong.ctx.plugin.body_values_cache[cache_key] = result_values
    end

    return result_values, result_err
end
_M.__get_values_request_query_value = function(try_b64)
    -- skip if phase init_worker
    if get_phase() == "init_worker" then
        return {}, nil
    end

    local values, err = body_parser:urlencoded("request.query", request_get_raw_query(), try_b64)
    if err then
        return nil, err
    end

    return values, nil
end
_M.__get_values_request_args = function (self, try_b64, rule_control)
    if get_phase() == "init_worker" then
        return {}, nil
    end

    local values = {}

    local query_values, err = self.__get_values_request_query_value()
    if err then
        return nil, err
    end

    local body_values, err = self.__get_values_request_body()
    if err then
        return nil, err
    end

    -- merge query_values and body_values
    if query_values then
        for k,v in pairs(query_values) do
            if not values[k] then
                if rule_control and rule_control.ignore_variables then
                    if rule_control.ignore_variables["request.query.value"] then
                        if rule_control.ignore_variables["request.query.value"][k] then
                            goto continue
                        end
                    end
                end
                values[k] = v
            end
            ::continue::
        end
    end
    if body_values then
        for k,v in pairs(body_values) do
            if not values[k] then
                if rule_control and rule_control.ignore_variables then
                    if rule_control.ignore_variables["request.body.value"] then
                        if rule_control.ignore_variables["request.body.value"][k] then
                            goto continue
                        end
                    end
                end
                values[k] = v
            end
            ::continue::
        end
    end

    return values, nil
end
_M.__get_values_request_raw_path = function()
    if get_phase() == "init_worker" then
        return {}, nil
    end

    local values = {}

    local raw_path = request_get_raw_path()
    if raw_path then
        values["request.raw_path"] = raw_path
    end

    return values, nil
end
_M.__get_values_basename = function()
    if get_phase() == "init_worker" then
        return {}, nil
    end

    local values = {}

    local raw_path = request_get_raw_path()
    if raw_path then
        local basename = string_match(raw_path, ".*/([^/]*)$")
        if basename then
            values["request.basename"] = basename
        end
    end

    return values, nil
end
_M.__get_values_request_raw_query = function()
    if get_phase() == "init_worker" then
        return {}, nil
    end

    local values = {}

    local raw_query = request_get_raw_query()
    if raw_query and raw_query ~= "" then
        values["request.raw_query"] = raw_query
    end

    return values, nil
end
_M.__get_values_request_headers_all = function()
    if get_phase() == "init_worker" then
        return {}, nil
    end

    local values = {}
    local headers = request_get_headers()
    for header_name, header_value in pairs(headers) do
        if type(header_value) == "table" then
            header_value = table.concat(header_value, ", ")
        end
        values["request.header.value:" .. header_name] = header_value
    end

    return values, nil
end
_M.__get_values_request_header = function(variable_with_header_name)
    if get_phase() == "init_worker" then
        return {}, nil
    end

    -- request.header.value:<header_name>
    local header_name = string_match(variable_with_header_name, "request%.header%.value%:(.*)")

    local values = {}

    local header_value = request_get_header(header_name)
    if header_value then
        values["request.header.value:" .. header_name] = header_value
    end

    return values, nil
end
_M.__get_values_request_cookie = function(try_b64)
    if get_phase() == "init_worker" then
        return {}, nil
    end

    local values = {}

    local function split(input, delimiter)
        local result = {}
        for match in (input .. delimiter):gmatch("(.-)" .. delimiter) do
            table.insert(result, match)
        end
        return result
    end

    -- use utils:urldecode() to decode the raw_string
    local cookie_header_value = request_get_header("Cookie") or ""
    if cookie_header_value == "" then
        return values, nil
    end

    -- DO NOT %HH DECODE HERE
    --local raw_string = utils:urldecode(cookie_header_value) -- decoding here creates issues with some cookies containing %3D (=) signs
    local raw_string = cookie_header_value
    local key_value_cookies = split(raw_string, ";")

    for _,pair in ipairs(key_value_cookies) do
        local key,value = string_match(pair, "([^=]+)=?(.*)")

        -- remove trailing and leading whitespaces from cookie name
        key = string_gsub(key, "^%s*(.-)%s*$", "%1")

        --[[table.insert(values, {
            [prefix .. ".name:"..key:lower()] = key
        })]]--

        local element_name = "request.cookie.name:" .. key:lower()
        local element_value = "request.cookie.value:" .. key:lower()
        if not values[element_name] then
            values[element_name] = key
        end

        -- if value starts with %7B%22 or %7b%22, then urldecode it
        -- since utils:urldecode decodes three times, I'm using ngx.unescape_uri here
        if string_match(value, "^%%7[bB]%%22") then
            value = ngx.unescape_uri(value)
        end

        -- usgin pcall as a "try-catch" alternative
        -- it doesn't need to catch any error, or return any feedback
        --[[if string_match(value, "^[%{%[]") and pcall(cjson.decode,value) then
            local cookie_json_flat = self:json("request.cookie", value, try_base64decode_if_possible)
            for _,vv in pairs(cookie_json_flat) do
                table.insert(values, {
                    [prefix .. ".value:"..key:lower()] = vv
                })
            end
        else
            table.insert(values, {
                [prefix .. ".value:"..key:lower()] = value
            })
        end]]--

        local cookie_val_json_decoded, err = pcall(function()
            -- try to decode cookie value as json
            if string_match(value, "^[%{%[]") then
                local cookie_json_flat, err = body_parser:json("request.cookie.json." .. key:lower(), value, try_b64)
                if err then
                    kong.log.debug("Error decoding cookie " .. key .. " value as JSON: " .. err)
                    goto notjson
                end
                for k,v in pairs(cookie_json_flat) do
                    local element_value_json = k
                    if not values[element_value_json] then
                        values[element_value_json] = v
                    end
                end
                return
            end

            ::notjson::
            if not values[element_value] then
                values[element_value] = value
            end
        end)

        --[[if not cookie_val_json_decoded then
            if not values[element_value] then
                values[element_value] = value
            end
        end]]--
    end

    return values, nil
end



_M.loop_rules = function(self, plugin_conf, raw_rules, phase)
    -- update module-level debug flag from plugin_conf for hot-path gating
    private_debug_enabled = plugin_conf.private_debug or false

    if #raw_rules > 0 then
        if private_debug_enabled then
            kong.log.debug("Looping rules for phase: " .. phase .. " / rule count: " .. tostring(#raw_rules) .. " / nginx worker number: " .. tostring(ngx.worker.id()))
        end

        for _,rule in pairs(raw_rules) do
            -- if plugin_conf.private_debug and request header x-karna-test-rule-id is set, filter rule.id for the header value
            if plugin_conf.private_debug then
                local test_rule_id = kong.request.get_header("x-karna-test-rule-id")
                if test_rule_id then
                    if test_rule_id ~= tostring(rule.id) then
                        goto continue
                    else
                        kong.log.inspect(rule)
                    end
                end
            end

            if rule.phase == phase then
                --kong.log.debug("Checking rule " .. tostring(rule.id) .. " for phase " .. phase)

                local rule_matched, matches = self:__match_rule_conditions(rule, plugin_conf)
                if rule_matched then
                    if private_debug_enabled then
                        kong.log.debug("----> (loop_rules) Rule " .. tostring(rule.id) .. " matched on phase " .. phase)
                        kong.log.inspect(rule)
                        kong.log.inspect(matches)
                    end

                    return true, rule, matches, nil
                end

                --return true, nil
            end

            ::continue::

        end

    end
end



_M.__match_op_rx = function(variable_name, value_to_match_on, regex)
    if variable_name and value_to_match_on then
        local matched_table = {}
        local m = ngx_re_match(value_to_match_on, regex, "sjo")
        if m then
            matched_table["matched_on"] = variable_name
            matched_table["matched_value"] = string.sub(value_to_match_on, 1, 100)
            for i=0,#m do
                matched_table["matched_group_"..i] = m[i]
            end

            return true, matched_table
        end
    end
    return false, nil
end
_M.__match_op_rx_negative = function(variable_name, value_to_match_on, regex)
    if variable_name and value_to_match_on then
        local matched_table = {}
        local m = ngx_re_match(value_to_match_on, regex, "sjo")
        if not m then
            matched_table["matched_on"] = variable_name
            matched_table["matched_value"] = string.sub(value_to_match_on, 1, 100)
            return true, matched_table
        end
    end
    return false, nil
end
_M.__match_op_beginswith = function(variable_name, value_to_match_on, string_to_match)
    if variable_name and value_to_match_on then
        local matched_table = {}
        local m = string_match(value_to_match_on, "^" .. string_to_match)
        if m then
            matched_table["matched_on"] = variable_name
            matched_table["matched_value"] = string.sub(value_to_match_on, 1, 100)
            return true, matched_table
        end
    end
    return false, nil
end
_M.__match_op_isset = function(values)
    for variable_name,orig_value in pairs(values) do
        if variable_name and orig_value then
            local matched_table = {}
            matched_table["matched_on"] = variable_name
            matched_table["matched_value"] = orig_value
            return true, matched_table
        end
    end

    return false, nil
end
_M.__match_op_isset_negative = function(values)
    if #values > 0 then
        return false, nil
    end

    return true, {}
end
_M.__match_op_libinjection_xss = function(variable_name, value_to_match_on)
    local matched_table = {}
    local isxss = libinjection.xss(value_to_match_on)
    if isxss then
        matched_table["matched_on"] = variable_name
        matched_table["matched_value"] = string.sub(value_to_match_on, 1, 100)
        return true, matched_table
    end
    return false, nil
end
_M.__match_op_libinjection_sqli = function(variable_name, value_to_match_on)
    local matched_table = {}
    local issqli = libinjection.sqli(value_to_match_on)
    if issqli then
        matched_table["matched_on"] = variable_name
        matched_table["matched_value"] = string.sub(value_to_match_on, 1, 100)
        return true, matched_table
    end
    return false, nil
end
_M.__match_op_pm = function(variable_name, valute_to_match_on, condition_value)
    -- split condition_value_resolved by whitespace
    local condition_values = {}
    for w in string_gmatch(condition_value, "%S+") do
        table_insert(condition_values, w)
    end
    for _,cv in pairs(condition_values) do
        -- prepend % to special characters in condition_value_resolved
        local safe_condition_value = string_gsub(cv, "([%^%$%(%)%%%.%[%]%*%+%-%?])", "%%%1")
        --debug("Trying to match: "..v:lower().." with "..safe_condition_value:lower())
        if string_match(valute_to_match_on:lower(), safe_condition_value:lower()) then
            local matched_table = {
                ["matched_on"] = variable_name,
                ["matched_value"] = string.sub(valute_to_match_on, 1, 100)
            }
            return true, matched_table
        end
    end
end
_M.__match_op_pmFromFile = function(variable_name, value_to_match_on, condition_value)
    local ka_dfiles = _M._ka_dfiles
    if ka_dfiles and ka_dfiles[condition_value] then
        for _,dvalue in pairs(ka_dfiles[condition_value]) do
            if string_match(value_to_match_on:lower(), dvalue:lower()) then
                local matched_table = {
                    ["matched_on"] = variable_name,
                    ["matched_value"] = string.sub(value_to_match_on, 1, 100)
                }
                return true, matched_table
            end
        end
    else
        debug("DFile not found: " .. condition_value)
    end
    return false, nil
end
_M.__match_op_eq = function(variable_name, value_to_match_on, condition_value)
    if value_to_match_on == condition_value then
        local matched_table = {
            ["matched_on"] = variable_name,
            ["matched_value"] = string.sub(value_to_match_on, 1, 100)
        }
        return true, matched_table
    end
    return false, nil
end
_M.__match_op_eq_negative = function(variable_name, value_to_match_on, condition_value)
    if value_to_match_on ~= condition_value then
        local matched_table = {
            ["matched_on"] = variable_name,
            ["matched_value"] = string.sub(value_to_match_on, 1, 100)
        }
        return true, matched_table
    end
    return false, nil
end
_M.__match_op_endswith = function(variable_name, value_to_match_on, condition_value)
    if value_to_match_on and condition_value then
        local escaped = string_gsub(condition_value, "([%^%$%(%)%%%.%[%]%*%+%-%?])", "%%%1")
        if string_match(value_to_match_on, escaped .. "$") then
            return true, {
                ["matched_on"] = variable_name,
                ["matched_value"] = string.sub(value_to_match_on, 1, 100)
            }
        end
    end
    return false, nil
end
_M.__match_op_endswith_negative = function(variable_name, value_to_match_on, condition_value)
    if value_to_match_on and condition_value then
        local escaped = string_gsub(condition_value, "([%^%$%(%)%%%.%[%]%*%+%-%?])", "%%%1")
        if not string_match(value_to_match_on, escaped .. "$") then
            return true, {
                ["matched_on"] = variable_name,
                ["matched_value"] = string.sub(value_to_match_on, 1, 100)
            }
        end
    end
    return false, nil
end

_M.__match_rule_conditions = function(self, rule, plugin_conf)
    -- check if rule has been removed by a rule_control
    if self:__rule_control_rule_removed(rule) then
        return false, nil
    end

    --kong.log.debug("\n\n")
    --kong.log.debug("Matching rule " .. tostring(rule.id) .. " for phase " .. rule.phase)
    
    -- __apply_transformation = function(self, tfunc, value)
    local rule_conditions = #rule.conditions
    local matched_conditions = 0
    local matches = {}
    local rx_matched_values_cross_conditions = {}


    --[[
        ██╗██╗██╗    ██╗ █████╗ ██████╗ ███╗   ██╗██╗███╗   ██╗ ██████╗ ██╗██╗
        ██║██║██║    ██║██╔══██╗██╔══██╗████╗  ██║██║████╗  ██║██╔════╝ ██║██║
        ██║██║██║ █╗ ██║███████║██████╔╝██╔██╗ ██║██║██╔██╗ ██║██║  ███╗██║██║
        ╚═╝╚═╝██║███╗██║██╔══██║██╔══██╗██║╚██╗██║██║██║╚██╗██║██║   ██║╚═╝╚═╝
        ██╗██╗╚███╔███╔╝██║  ██║██║  ██║██║ ╚████║██║██║ ╚████║╚██████╔╝██╗██╗
        ╚═╝╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝          
    
        do not change the value of any object inside "rule" table
        nor modify its structure or content, and do not cache any value inside "condition" or "variable" tables.
        changing those objects will have side effects on other rules evaluation since those objects are shared across all rules.
    ]]--
    for i,condition in pairs(rule.conditions) do
        for _,variable in pairs(condition.variables) do

            if private_debug_enabled then
                kong.log.debug("----> (rule " .. tostring(rule.id) .. ") Evaluating condition " .. tostring(i) .. "/" .. tostring(rule_conditions) .. " on variable: " .. tostring(variable) .. " with operator: " .. tostring(condition.op) .. " and value: " .. tostring(condition.value))
            end

            local values, err = nil

            if kong.ctx and kong.ctx.plugin then
                if kong.ctx.plugin.ka_variable_cache[variable] then
                    values = kong.ctx.plugin.ka_variable_cache[variable]
                end
            end

            if private_debug_enabled then
                kong.log.inspect(rx_matched_values_cross_conditions)
            end

            if not values then
                -- if condition operator is not isSet or !isSet

                if variable == "request.arg.value" then
                    values, err = self:__get_values_request_args(false, rule.rule_control)
                elseif string_find(variable, "^request%.arg%.value%:") then
                    local arg_name = string_match(variable, "^request%.arg%.value%:(.*)")
                    local all_values, all_err = self:__get_values_request_args(false, rule.rule_control)
                    if all_values then
                        values = {}
                        for k, v in pairs(all_values) do
                            if string_find(k, "%." .. arg_name .. "$") or string_find(k, ":" .. arg_name .. "$") then
                                values[k] = v
                            end
                        end
                    end
                    err = all_err
                end

                if variable == "request.raw_path" then
                    values, err = self.__get_values_request_raw_path()
                end

                if variable == "request.path_with_query" then
                    if get_phase() ~= "init_worker" then
                        values = { ["request.path_with_query"] = tostring(request_get_path_with_query()) }
                    end
                end

                if variable == "request.basename" then
                    values, err = self.__get_values_basename()
                end

                if variable == "request.raw_query" then
                    values, err = self.__get_values_request_raw_query()
                end

                if variable == "request.header.value" then
                    values, err = self.__get_values_request_headers_all()
                elseif string_find(variable, "request.header.value:") then
                    values, err = self.__get_values_request_header(variable)
                end

                if variable == "request.cookie.value" then
                    values, err = self.__get_values_request_cookie(false)
                end

                if string_find(variable, "^request%.body%.multipart%.") then
                    local body_values = self.__get_values_request_body()
                    if body_values and body_values[variable] then
                        values = { [variable] = body_values[variable] }
                    end
                end

                -- TX variable with regex pattern (e.g. group_rx:rfi_parameter_.*)
                if string_find(variable, "^group_rx%:") then
                    local pattern = string_match(variable, "^group_rx%:(.*)")
                    if pattern and kong.ctx.plugin.tx_variables then
                        values = {}
                        for tx_name, tx_value in pairs(kong.ctx.plugin.tx_variables) do
                            if ngx_re_match(tx_name, pattern, "jo") then
                                values["tx." .. tx_name] = tx_value
                            end
                        end
                    end
                end

                if string.find(variable, "^group%:[0-9]+$") then
                    values = {[variable] = rx_matched_values_cross_conditions[variable]}
                end

                -- MCP variables: resolved straight from kong.ctx.plugin.mcp,
                -- which is populated in access phase by ka_mcp.parse_request().
                -- Supports any path under mcp.* via dotted lookup; the inspection
                -- table additionally has flattened mcp.params.<json-path> entries.
                if string_find(variable, "^mcp%.") then
                    local mcp = kong.ctx.plugin.mcp
                    if mcp then
                        local v
                        local short = variable:sub(5)
                        -- mcp.event.* — per-SSE-event variables, only set
                        -- while ka_mcp.body_filter is iterating events.
                        if short:sub(1,6) == "event." then
                            local ev = mcp.event
                            if ev then
                                local subpath = short:sub(7)
                                if subpath == "type" then v = ev.type
                                elseif subpath == "id"   then v = ev.id
                                elseif subpath == "data" then v = ev.data
                                elseif subpath == "retry" then v = ev.retry
                                elseif subpath == "jsonrpc_method" then
                                    v = ev.data_decoded and ev.data_decoded.method
                                elseif subpath == "jsonrpc_kind" then
                                    if ev.data_decoded then
                                        local ok, kind = ka_mcp._validate_jsonrpc(ev.data_decoded)
                                        if ok then v = kind end
                                    end
                                elseif subpath:sub(1,5) == "data." then
                                    v = ka_mcp._lookup_path(ev.data_decoded, subpath:sub(6))
                                end
                            end
                        -- Try direct top-level fields first.
                        elseif short == "transport"        then v = mcp.transport
                        elseif short == "protocol_version" then v = mcp.protocol_version
                        elseif short == "session_id"   then v = mcp.session_id
                        elseif short == "origin"       then v = mcp.origin
                        elseif short == "message_kind" then v = mcp.message_kind
                        elseif short == "method"       then v = mcp.method
                        elseif short == "id"           then v = mcp.id
                        elseif short == "is_streaming" then v = mcp.is_streaming
                        elseif short == "tool.name"    then v = mcp.tool and mcp.tool.name
                        elseif short == "resource.uri" then v = mcp.resource and mcp.resource.uri
                        elseif short == "prompt.name"  then v = mcp.prompt and mcp.prompt.name
                        elseif short == "client.name"     then v = mcp.client and mcp.client.name
                        elseif short == "client.version"  then v = mcp.client and mcp.client.version
                        elseif short == "server.name"     then v = mcp.server and mcp.server.name
                        elseif short == "server.version"  then v = mcp.server and mcp.server.version
                        elseif short == "error.code"      then v = mcp.error and mcp.error.code
                        elseif short == "error.message"   then v = mcp.error and mcp.error.message
                        else
                            -- Fall back to dotted-path lookup on params and tool.arguments.
                            v = ka_mcp._lookup_path(mcp, short)
                        end
                        if type(v) == "boolean" then v = v and "true" or "false" end
                        -- Always emit at least one entry so context-aware operators
                        -- like mcp_jsonrpc_valid still run when the request was
                        -- detected as MCP but the specific field is missing
                        -- (e.g. malformed envelope leaves mcp.method nil).
                        values = { [variable] = tostring(v or "") }
                    end
                end

                if variable and values then
                    if kong.ctx and kong.ctx.plugin then
                        kong.ctx.plugin.ka_variable_cache[variable] = values
                    end
                end

            end

            --kong.log.inspect(values)

            if kong.ctx and kong.ctx.plugin then
                if values and #kong.ctx.plugin.rule_controls.remove_target_from_all_rules > 0 then
                    -- remove all entries from values that are equals to entried in kong.ctx.plugin.rule_controls.remove_target_from_all_rules
                    for _,remove_target in pairs(kong.ctx.plugin.rule_controls.remove_target_from_all_rules) do
                        if values[remove_target] then
                            values[remove_target] = nil
                        end
                    end
                end
            end

            if values then
                local loop_counter = 0
                local rule_condition_has_matched, matched_table = false, nil
                for variable_name,orig_value in pairs(values) do
                    loop_counter = loop_counter + 1
                    local condition_value_resolved = condition.value

                    -- apply transformation_functions
                    local value_to_match_on = orig_value
                    local multi_match_values = {}
                    for _,tfunc in pairs(condition.transform) do
                        if type(value_to_match_on) == "string" then
                            value_to_match_on = self:__apply_transformation(tfunc, value_to_match_on)
                            if condition.multi_match then
                                table_insert(multi_match_values, value_to_match_on)
                            end
                        else
                            if private_debug_enabled then
                                kong.log.debug("Value is not a string, skipping transformation function " .. tostring(tfunc))
                            end
                        end
                    end

                    -- convert %{group:[0-9]+} on value_to_match_on to the value of corresponding rx_matched_values_cross_conditions
                    if string.find(condition_value_resolved, "%%%{(group%:[0-9]+)%}") then
                        if private_debug_enabled then
                            kong.log.debug("--------> condition_value_resolved before replacement: " .. tostring(condition_value_resolved))
                        end

                        for rx_group in string.gmatch(condition_value_resolved, "%%%{(group%:[0-9]+)%}") do
                            if private_debug_enabled then
                                kong.log.debug("--------> rx_group in condition_value_resolved: " .. tostring(rx_group))
                            end
                            if rx_matched_values_cross_conditions[rx_group] then
                                condition_value_resolved = string.gsub(condition_value_resolved, "%%%{" .. rx_group .. "%}", rx_matched_values_cross_conditions[rx_group])
                                if private_debug_enabled then
                                    kong.log.debug("Replaced " .. tostring(rx_group) .. " in condition_value_resolved resulting in value: " .. tostring(condition_value_resolved))
                                end
                            end
                        end
                    end

                    -- resolve %{request_headers.<name>} macros in condition_value_resolved
                    if string.find(condition_value_resolved, "%%%{request_headers%.") then
                        for header_name in string.gmatch(condition_value_resolved, "%%%{request_headers%.([^}]+)%}") do
                            local header_value = request_get_header(header_name)
                            if header_value then
                                condition_value_resolved = string.gsub(
                                    condition_value_resolved,
                                    "%%%{request_headers%." .. header_name .. "%}",
                                    header_value
                                )
                            end
                        end
                    end

                    -- resolve %{tx.*} variables from plugin_conf
                    if plugin_conf and string.find(condition_value_resolved, "%%{tx%.") then
                        if string.find(condition_value_resolved, "%%{tx%.allowed_request_content_type_charset}") then
                            local vals = ""
                            for _, cs in pairs(plugin_conf.request_content_type_charset_allowed) do
                                vals = vals .. " " .. cs
                            end
                            condition_value_resolved = string_gsub(condition_value_resolved, "%%{tx%.allowed_request_content_type_charset}", vals)
                        end
                        if string.find(condition_value_resolved, "%%{tx%.allowed_http_versions}") then
                            condition_value_resolved = string_gsub(condition_value_resolved, "%%{tx%.allowed_http_versions}", "1.0 1.1 2 3")
                        end
                        if string.find(condition_value_resolved, "%%{tx%.restricted_extensions}") then
                            local vals = ""
                            for _, ext in pairs(plugin_conf.restricted_extensions) do
                                vals = vals .. " " .. ext
                            end
                            condition_value_resolved = string_gsub(condition_value_resolved, "%%{tx%.restricted_extensions}", vals)
                        end
                        if string.find(condition_value_resolved, "%%{tx%.allowed_request_content_type}") then
                            local vals = ""
                            for _, ct in pairs(plugin_conf.request_content_type_allowed) do
                                vals = vals .. " " .. ct
                            end
                            condition_value_resolved = string_gsub(condition_value_resolved, "%%{tx%.allowed_request_content_type}", vals)
                        end
                        if string.find(condition_value_resolved, "%%{tx%.restricted_headers_basic}") then
                            local vals = ""
                            for _, h in pairs(plugin_conf.request_headers_denied) do
                                vals = vals .. " " .. h
                            end
                            condition_value_resolved = string_gsub(condition_value_resolved, "%%{tx%.restricted_headers_basic}", vals)
                        end
                        -- resolve dynamic TX variables from tx_variables store
                        condition_value_resolved = string_gsub(condition_value_resolved, "%%{tx%.([^}]+)}", function(tx_name)
                            if kong.ctx.plugin.tx_variables and kong.ctx.plugin.tx_variables[tx_name] then
                                return kong.ctx.plugin.tx_variables[tx_name]
                            end
                            return ""
                        end)
                    end

                    rule_condition_has_matched, matched_table = false, nil

                    -- build list of values to try matching on
                    -- with multi_match, try each intermediate transformation result
                    local values_to_try = { value_to_match_on }
                    if condition.multi_match and #multi_match_values > 0 then
                        values_to_try = multi_match_values
                    end

                    for _,try_value in pairs(values_to_try) do
                        if private_debug_enabled then
                            kong.log.debug("----> try_value on " .. variable_name .. ": [" .. tostring(try_value) .. "] (len=" .. tostring(#tostring(try_value)) .. ")")
                        end
                        -- operators
                        if condition.op == "isSet" then
                            rule_condition_has_matched, matched_table = self.__match_op_isset(values)
                        end
                        if condition.op == "beginsWith" then
                            rule_condition_has_matched, matched_table = self.__match_op_beginswith(variable_name, try_value, condition_value_resolved)
                        end
                        if condition.op == "rx" then
                            rule_condition_has_matched, matched_table = self.__match_op_rx(variable_name, try_value, condition_value_resolved)
                            if rule_condition_has_matched and matched_table then
                                for krx,vrx in pairs(matched_table) do
                                    local m = string.match(krx, "^matched%_group%_([0-9]+)$")
                                    if m then
                                        rx_matched_values_cross_conditions["group:" .. m] = vrx
                                    end
                                end
                            end
                        end
                        if condition.op == "!rx" then
                            rule_condition_has_matched, matched_table = self.__match_op_rx_negative(variable_name, try_value, condition_value_resolved)
                        end
                        if condition.op == "libinjection_xss" then
                            rule_condition_has_matched, matched_table = self.__match_op_libinjection_xss(variable_name, try_value)
                        end
                        if condition.op == "libinjection_sqli" then
                            rule_condition_has_matched, matched_table = self.__match_op_libinjection_sqli(variable_name, try_value)
                        end
                        if condition.op == "pm" then
                            rule_condition_has_matched, matched_table = self.__match_op_pm(variable_name, try_value, condition_value_resolved)
                        end
                        if condition.op == "pmFromFile" then
                            rule_condition_has_matched, matched_table = self.__match_op_pmFromFile(variable_name, try_value, condition_value_resolved)
                        end
                        if condition.op == "eq" then
                            rule_condition_has_matched, matched_table = self.__match_op_eq(variable_name, try_value, condition_value_resolved)
                        end
                        if condition.op == "!eq" then
                            rule_condition_has_matched, matched_table = self.__match_op_eq_negative(variable_name, try_value, condition_value_resolved)
                        end
                        if condition.op == "endsWith" then
                            rule_condition_has_matched, matched_table = self.__match_op_endswith(variable_name, try_value, condition_value_resolved)
                        end
                        if condition.op == "!endsWith" then
                            rule_condition_has_matched, matched_table = self.__match_op_endswith_negative(variable_name, try_value, condition_value_resolved)
                        end
                        if condition.op == "within" then
                            local within_values = {}
                            for w in string_gmatch(condition_value_resolved, "%S+") do
                                table_insert(within_values, w)
                            end
                            for _, wv in pairs(within_values) do
                                local escaped = string_gsub(wv, "([%^%$%(%)%%%.%[%]%*%+%-%?])", "%%%1")
                                if string_match(try_value, "^" .. escaped .. "$") then
                                    rule_condition_has_matched = true
                                    matched_table = { matched_on = variable_name, matched_value = try_value }
                                    break
                                end
                            end
                        end
                        if condition.op == "!within" then
                            local within_values = {}
                            for w in string_gmatch(condition_value_resolved, "%S+") do
                                table_insert(within_values, w)
                            end
                            local found = false
                            for _, wv in pairs(within_values) do
                                local escaped = string_gsub(wv, "([%^%$%(%)%%%.%[%]%*%+%-%?])", "%%%1")
                                if string_match(try_value, "^" .. escaped .. "$") then
                                    found = true
                                    break
                                end
                            end
                            if not found then
                                rule_condition_has_matched = true
                                matched_table = { matched_on = variable_name, matched_value = try_value }
                            end
                        end
                        if condition.op == "mcp_method_in" then
                            -- Glob match against a space-separated list of patterns.
                            -- Patterns: literal | "tools/*" | "notifications/**".
                            local patterns = {}
                            for w in string_gmatch(tostring(condition_value_resolved or ""), "%S+") do
                                table_insert(patterns, w)
                            end
                            if try_value and ka_mcp._method_matches(tostring(try_value), patterns) then
                                rule_condition_has_matched = true
                                matched_table = { matched_on = variable_name, matched_value = try_value }
                            end
                        end
                        if condition.op == "mcp_jsonrpc_valid" then
                            -- Match if the envelope is INVALID. No-op if no MCP context.
                            local mcp = kong.ctx.plugin.mcp
                            if mcp and mcp._raw then
                                local decoded = cjson_safe.decode(mcp._raw)
                                local ok = decoded and ka_mcp._validate_jsonrpc(decoded)
                                if not ok then
                                    rule_condition_has_matched = true
                                    matched_table = { matched_on = variable_name, matched_value = "invalid_envelope" }
                                end
                            end
                        end
                        -- /operators

                        if rule_condition_has_matched then
                            break
                        end
                    end

                    if rule_condition_has_matched then
                        matches[#matches+1] = matched_table
                        if private_debug_enabled then
                            kong.log.debug("----> Rule " .. tostring(rule.id) .. " matched on condition " .. tostring(i) .. " with value: " .. tostring(value_to_match_on))
                        end
                        matched_conditions = matched_conditions + 1

                        -- execute setvar actions to populate TX variables for chained conditions
                        if rule.action and rule.action.setvar and kong.ctx.plugin.tx_variables then
                            for _, sv in pairs(rule.action.setvar) do
                                local resolved_name = sv.var_name
                                local resolved_value = sv.var_value
                                -- resolve %{MATCHED_VAR_NAME}
                                resolved_name = string_gsub(resolved_name, "%%{MATCHED_VAR_NAME}", variable_name)
                                -- resolve %{tx.N} (regex capture groups)
                                resolved_value = string_gsub(resolved_value, "%%{tx%.(%d+)}", function(n)
                                    return rx_matched_values_cross_conditions["group:" .. n] or ""
                                end)
                                -- skip anomaly score variables
                                if not string_find(resolved_name, "anomaly_score") then
                                    kong.ctx.plugin.tx_variables[resolved_name] = resolved_value
                                    if private_debug_enabled then
                                        kong.log.debug("----> setvar: tx." .. resolved_name .. " = " .. resolved_value)
                                    end
                                end
                            end
                        end

                        if matched_conditions == #rule.conditions then
                            goto all_conditions_matched
                        end
                    end
                end

                if loop_counter == 0 then
                    if condition.op == "!isSet" then
                        matches[#matches+1] = {
                            matched_on = table.concat(condition.variables, ","),
                            matched_value = ""
                        }
                        if private_debug_enabled then
                            kong.log.debug("----> Rule " .. tostring(rule.id) .. " matched on condition " .. tostring(i))
                        end
                        matched_conditions = matched_conditions + 1
                        goto all_conditions_matched
                    end
                end
            else
                if private_debug_enabled then
                    kong.log.debug("No values found for variable " .. tostring(variable) .. " in condition " .. tostring(i) .. " of rule " .. tostring(rule.id))
                end
            end
        end
    end

    ::all_conditions_matched::

    if matched_conditions > 0 then
        if rule_conditions == matched_conditions then
            if private_debug_enabled then
                kong.log.debug("Rule " .. tostring(rule.id) .. " matched on all conditions: " .. tostring(matched_conditions) .. " / " .. tostring(rule_conditions))
            end
            return true, matches
        else
            if private_debug_enabled then
                kong.log.debug("Rule " .. tostring(rule.id) .. " matched on " .. tostring(matched_conditions) .. " / " .. tostring(rule_conditions) .. " conditions")
            end
            return false, matches
        end
    else
        if private_debug_enabled then
            kong.log.debug("Rule " .. tostring(rule.id) .. " matched on " .. tostring(matched_conditions) .. " / " .. tostring(rule_conditions) .. " conditions")
            kong.log.debug("\n")
        end
        return false, nil
    end
end

--[==[
_M.__match_rule_conditions_old = function(self, rule, plugin_conf, ka_dfiles)
    if not kong or not kong.ctx or not kong.ctx.plugin then
        debug("skipping matching rule conditions: kong.ctx.plugin is not set")
        return false, {}
    end
    -- number of conditions to match
    -- inspect(rule)

    --debug("-------------------------- PLUGIN INSPECTION TABLE:")
    --inspect(kong.ctx.plugin.inspection_table)

    --if not kong.ctx.plugin.rules_matched then
    --    kong.ctx.plugin.rules_matched = {}
    --end

    local filter_inspection_table_value_by_key_pattern = {}
    local filter_inspection_table_value_by_key_name = {}

    if rule.rule_control then
        --debug("Rule control found on rule: "..rule.id)
        --inspect(rule.rule_control)
        for _,rulec in pairs(rule.rule_control) do
            if rulec.remove_target_pattern then
                --debug("Setting filter_inspection_table_value_by_key_pattern to: "..rulec.remove_target_pattern)
                --filter_inspection_table_value_by_key_pattern = rulec.remove_target_pattern
                table_insert(filter_inspection_table_value_by_key_pattern, rulec.remove_target_pattern)
            end

            if rulec.remove_target_name then
                --debug("Setting filter_inspection_table_value_by_key_name to: "..rulec.remove_target_name)
                --filter_inspection_table_value_by_key_name = rulec.remove_target_name
                table_insert(filter_inspection_table_value_by_key_name, rulec.remove_target_name)
            end
        end
    end

    local conditions_to_match = #rule.conditions
    local conditions_matched = 0
    --local matched_parts = {}
    --local action = rule.action

    --if not kong.ctx.plugin.rule_matched_parts then
        kong.ctx.plugin.rule_matched_parts = {}
    --end

    for _,condition in pairs(rule.conditions) do
        kong.ctx.plugin.rule_inspection_table = nil

        self:__set_rule_inspection_table(rule, condition, plugin_conf)

        if #kong.ctx.plugin.rule_inspection_table <= 0 then
            kong.ctx.plugin.rule_inspection_table = {
                {
                    ["none"] = ""
                }
            }
        end

        local increment_condition_matched = false

        if condition.op then
            if condition.value then

                local condition_value_resolved = string_gsub(condition.value, "%%%{request%_headers%.host%}", request_get_host())

                -- replace %{group:1} with matched_group_1
                if string_match(condition_value_resolved, "%%%{group:%d+}") then
                    --inspect(kong.ctx.plugin.rule_matched_parts)
                    local group_number = tonumber(string_match(condition_value_resolved, "%%%{group:(%d+)}"))
                    if group_number then
                        for _,v in pairs(kong.ctx.plugin.rule_matched_parts) do
                            if v["matched_group_"..group_number] then
                                condition_value_resolved = string_gsub(condition_value_resolved, "%%%{group:"..group_number.."}", v["matched_group_"..group_number])
                            end
                        end
                    end
                end

                -- replace %{tx.allowed_http_versions} with supported HTTP versions
                if string_match(condition_value_resolved, "%%%{tx%.allowed_http_versions}") then
                    local allowed_http_versions = "1.0 1.1 2 3"
                    --debug("Replacing %{tx.allowed_http_versions} with: "..allowed_http_versions)
                    condition_value_resolved = string_gsub(condition_value_resolved, "%%%{tx%.allowed_http_versions}", allowed_http_versions)
                end

                -- replace %{tx.restricted_extensions} with plugin_conf.restricted_extensions string separated by whitespace
                if string_match(condition_value_resolved, "%%%{tx%.restricted_extensions}") then
                    local restricted_extensions = ""
                    for _,ext in pairs(plugin_conf.restricted_extensions) do
                        restricted_extensions = restricted_extensions .. " " .. ext
                    end
                    --debug("Replacing %{tx.restricted_extensions} with: "..restricted_extensions)
                    condition_value_resolved = string_gsub(condition_value_resolved, "%%%{tx%.restricted_extensions}", restricted_extensions)
                end

                -- replace %{tx.allowed_request_content_type} with plugin_conf.request_content_type_allowed string separated by whitespace
                if string_match(condition_value_resolved, "%%%{tx%.allowed_request_content_type}") then
                    local allowed_request_content_type = ""
                    for _,content_type in pairs(plugin_conf.request_content_type_allowed) do
                        allowed_request_content_type = allowed_request_content_type .. " " .. content_type
                    end
                    --debug("Replacing %{tx.allowed_request_content_type} with: "..allowed_request_content_type)
                    condition_value_resolved = string_gsub(condition_value_resolved, "%%%{tx%.allowed_request_content_type}", allowed_request_content_type)
                end

                -- replace %{tx.restricted_headers_basic} with plugin_conf.request_headers_denied string separated by whitespace
                if string_match(condition_value_resolved, "%%%{tx%.restricted_headers_basic}") then
                    local restricted_headers_basic = ""
                    for _,header in pairs(plugin_conf.request_headers_denied) do
                        restricted_headers_basic = restricted_headers_basic .. " " .. header
                    end
                    --debug("Replacing %{tx.restricted_headers_basic} with: "..restricted_headers_basic)
                    condition_value_resolved = string_gsub(condition_value_resolved, "%%%{tx%.restricted_headers_basic}", restricted_headers_basic)
                end

                --debug("Condition value resolved: "..condition_value_resolved)

                --debug("-------------> RULE INSPECTION TABLE (POST PROCESSING):")
                --inspect(kong.ctx.plugin.rule_inspection_table)

                for _,value in pairs(kong.ctx.plugin.rule_inspection_table) do
                    for k,v in pairs(value) do
                        local k_filtered_by_rule_control = false

                        if #filter_inspection_table_value_by_key_pattern > 0 then
                            --debug("Filtering inspection table found")
                            --debug("-> check if key "..k.." matches pattern")
                            for _,p in pairs(filter_inspection_table_value_by_key_pattern) do
                                if string_match(k, p) then
                                    --debug("--> Filtering inspection table value by key pattern: "..p)
                                    k_filtered_by_rule_control = true
                                end
                            end
                        end

                        if #filter_inspection_table_value_by_key_name > 0 then
                            --debug("Filtering inspection table found")
                            --debug("-> check if key "..k.." matches name")
                            for _,p in pairs(filter_inspection_table_value_by_key_name) do
                                if k == p then
                                    --debug("--> Filtering inspection table value by key name: "..p.." for rule id "..rule.id)
                                    k_filtered_by_rule_control = true
                                end
                            end
                        end

                        if not k_filtered_by_rule_control then
                            -- Global matching regex
                            if condition.op == "grx" then
                                local iterator, err = ngx.re.gmatch(v, condition_value_resolved, "s")
                                if not iterator then
                                    debug("Error matching regex: "..err)
                                else
                                    increment_condition_matched = true
                                end

                                while true do
                                    local m, err = iterator()
                                    if err then
                                        debug("Error matching regex: "..err)
                                        break
                                    end

                                    if not m then
                                        break
                                    end

                                    local matched_table = {}
                                    matched_table["matched_on"] = k
                                    matched_table["matched_value"] = v
                                    for i=0,#m do
                                        matched_table["matched_group_"..i] = m[i]
                                    end
                                    table_insert(kong.ctx.plugin.rule_matched_parts, matched_table)
                                end
                            end

                            -- Regex
                            if condition.op == "rx" then

                                -- remove \r and \n from value
                                --v = string_gsub(v, "[\r\n]", "")
                                local m = ngx_re_match(v, condition_value_resolved, "sjo")
                                if m then
                                    local matched_table = {}
                                    --debug("---- CONDITION MATCHED ".. conditions_matched .." ----> op:"..condition.op.." v:"..v.." condition_value:" .. condition_value_resolved)
                                    increment_condition_matched = true
                                    matched_table["matched_on"] = k
                                    matched_table["matched_value"] = v
                                    for i=0,#m do
                                        matched_table["matched_group_"..i] = m[i]
                                    end
                                    table_insert(kong.ctx.plugin.rule_matched_parts, matched_table)
                                end

                            end

                            if condition.op == "!rx" then
                                if v then
                                    -- remove \r and \n from value
                                    v = string_gsub(v, "[\r\n]", "")
                                    local m = ngx_re_match(v, condition_value_resolved, "sjo")
                                    if not m then
                                        --local matched_table = {}
                                        --debug("---- CONDITION MATCHED ".. conditions_matched .." ----> op:"..condition.op.." v:"..v.." condition_value:" .. condition_value_resolved)
                                        increment_condition_matched = true
                                    end
                                end
                            end

                            if condition.op == "isSet" then
                                --debug("-------------------------> Checking if variable is set: "..k)
                                for _,variable_name in pairs(condition.variables) do
                                    --debug("--------------------------_> Checking if "..k.." is set and if it matches "..variable_name)
                                    if k == variable_name then
                                        --debug("----> isSet matched: "..k.." = "..variable_name)
                                        --debug("---- CONDITION MATCHED ".. conditions_matched .." ----> op:"..condition.op.." v:"..v.." condition_value:" .. condition_value_resolved)
                                        increment_condition_matched = true
                                        table_insert(kong.ctx.plugin.rule_matched_parts, { ["matched_on"] = k, ["matched_value"] = v })
                                        break
                                    end
                                end
                            end

                            -- !isSet
                            if condition.op == "!isSet" then
                                local variable_is_set = false
                                for _,variable_name in pairs(condition.variables) do
                                    if k == variable_name then
                                        variable_is_set = true
                                    end
                                end
                                if not variable_is_set then
                                    --debug("---- CONDITION MATCHED ".. conditions_matched .." ----> op:"..condition.op.." v:"..v.." condition_value:" .. condition_value_resolved)
                                    increment_condition_matched = true
                                    --table_insert(kong.ctx.plugin.rule_matched_parts, { ["matched_on"] = k, ["matched_value"] = v })
                                end
                            end

                            -- eq
                            if condition.op == "eq" then
                                if v == condition_value_resolved then
                                    --debug("---- CONDITION MATCHED ".. conditions_matched .." ----> op:"..condition.op.." v:"..v.." condition_value:" .. condition_value_resolved)
                                    increment_condition_matched = true
                                    table_insert(kong.ctx.plugin.rule_matched_parts, { ["matched_on"] = k, ["matched_value"] = v })
                                end
                            end

                            -- !eq
                            if condition.op == "!eq" then
                                if v then
                                    if v ~= condition_value_resolved then
                                        --debug("---- CONDITION MATCHED ".. conditions_matched .." ----> op:"..condition.op.." v:"..v.." condition_value:" .. condition_value_resolved)
                                        increment_condition_matched = true
                                        --table_insert(kong.ctx.plugin.rule_matched_parts, { ["matched_on"] = k, ["matched_value"] = v })
                                    end
                                end
                            end

                            -- Greater or equal than
                            if condition.op == "ge" then
                                if tonumber(v) then
                                    if tonumber(v) >= tonumber(condition_value_resolved) then
                                        --if k ~= "var:paranoia_level" then
                                            --debug("---- CONDITION MATCHED ".. conditions_matched .." ----> op:"..condition.op.." v:"..v.." condition_value:" .. condition_value_resolved)
                                            increment_condition_matched = true
                                            table_insert(kong.ctx.plugin.rule_matched_parts, { ["matched_on"] = k, ["matched_value"] = v })
                                        --end
                                    end
                                end
                            end

                            -- gt
                            if condition.op == "gt" then
                                if v and tonumber(v) and condition_value_resolved and tonumber(condition_value_resolved) then
                                    if tonumber(v) > tonumber(condition_value_resolved) then
                                        --debug("---- CONDITION MATCHED ".. conditions_matched .." ----> op:"..condition.op.." v:"..v.." condition_value:" .. condition_value_resolved)
                                        increment_condition_matched = true
                                        table_insert(kong.ctx.plugin.rule_matched_parts, { ["matched_on"] = k, ["matched_value"] = v })
                                    end
                                end
                            end

                            -- lt
                            if condition.op == "lt" then
                                --debug("executing operator lt: "..v.." < "..condition_value_resolved)
                                if v and tonumber(v) and condition_value_resolved and tonumber(condition_value_resolved) then
                                    if tonumber(v) < tonumber(condition_value_resolved) then
                                        --debug("---- CONDITION MATCHED ".. conditions_matched .." ----> op:"..condition.op.." v:"..v.." condition_value:" .. condition_value_resolved)
                                        increment_condition_matched = true
                                        table_insert(kong.ctx.plugin.rule_matched_parts, { ["matched_on"] = k, ["matched_value"] = v })
                                    end
                                end
                            end

                            -- begins with
                            if condition.op == "beginsWith" then
                                local fixed_condition_value = string_gsub(condition_value_resolved, "([%^%$%(%)%%%.%[%]%*%+%-%?])", "%%%1")
                                if string_match(v, "^"..fixed_condition_value) then
                                    --debug("---- CONDITION MATCHED ".. conditions_matched .." ----> op:"..condition.op.." v:"..v.." condition_value:" .. condition_value_resolved)
                                    increment_condition_matched = true
                                    table_insert(kong.ctx.plugin.rule_matched_parts, { ["matched_on"] = k, ["matched_value"] = v })
                                end
                            end

                            -- !beginsWith
                            if condition.op == "!beginsWith" then
                                if v then
                                    local fixed_condition_value = string_gsub(condition_value_resolved, "([%^%$%(%)%%%.%[%]%*%+%-%?])", "%%%1")
                                    if not string_match(v, "^"..fixed_condition_value) then
                                        --debug("---- CONDITION MATCHED ".. conditions_matched .." ----> op:"..condition.op.." v:"..v.." condition_value:" .. condition_value_resolved)
                                        increment_condition_matched = true
                                        --table_insert(kong.ctx.plugin.rule_matched_parts, { ["matched_on"] = k, ["matched_value"] = v })
                                    end
                                end
                            end

                            -- endsWith
                            if condition.op == "endsWith" then
                                if string_match(v, condition_value_resolved.."$") then
                                    --debug("---- CONDITION MATCHED ".. conditions_matched .." ----> op:"..condition.op.." v:"..v.." condition_value:" .. condition_value_resolved)
                                    increment_condition_matched = true
                                    table_insert(kong.ctx.plugin.rule_matched_parts, { ["matched_on"] = k, ["matched_value"] = v })
                                end
                            end

                            -- !endsWith
                            if condition.op == "!endsWith" then
                                if v then
                                    if not string_match(v, condition_value_resolved.."$") then
                                        --debug("---- CONDITION MATCHED ".. conditions_matched .." ----> op:"..condition.op.." v:"..v.." condition_value:" .. condition_value_resolved)
                                        increment_condition_matched = true
                                        --table_insert(kong.ctx.plugin.rule_matched_parts, { ["matched_on"] = k, ["matched_value"] = v })
                                    end
                                end
                            end

                            -- contains
                            if condition.op == "contains" then
                                local fixed_condition_value = string_gsub(condition_value_resolved, "([%^%$%(%)%%%.%[%]%*%+%-%?])", "%%%1")
                                if string_match(v, fixed_condition_value) then
                                    --debug("---- CONDITION MATCHED ".. conditions_matched .." ----> op:"..condition.op.." v:"..v.." condition_value:" .. fixed_condition_value)
                                    increment_condition_matched = true
                                    table_insert(kong.ctx.plugin.rule_matched_parts, { ["matched_on"] = k, ["matched_value"] = v })
                                end
                            end

                            -- string_match
                            if condition.op == "string_match" then
                                if string_match(v, condition_value_resolved) then
                                    --debug("---- CONDITION MATCHED ".. conditions_matched .." ----> op:"..condition.op.." v:"..v.." condition_value:" .. condition_value_resolved)
                                    increment_condition_matched = true
                                    table_insert(kong.ctx.plugin.rule_matched_parts, { ["matched_on"] = k, ["matched_value"] = v })
                                end
                            end

                            -- within
                            if condition.op == "within" then
                                -- split condition_value_resolved by whitespace
                                local condition_values = {}
                                for w in string_gmatch(condition_value_resolved, "%S+") do
                                    table_insert(condition_values, w)
                                end

                                for _,cv in pairs(condition_values) do
                                    local fixed_condition_value = string_gsub(cv, "([%^%$%(%)%%%.%[%]%*%+%-%?])", "%%%1")
                                    if string_match(v, "^"..fixed_condition_value.."$") then
                                        --debug("---- CONDITION MATCHED ".. conditions_matched .." ----> op:"..condition.op.." v:"..v.." condition_value:" .. condition_value_resolved)
                                        increment_condition_matched = true
                                        table_insert(kong.ctx.plugin.rule_matched_parts, { ["matched_on"] = k, ["matched_value"] = v })
                                    end
                                end
                            end

                            -- !within
                            if condition.op == "!within" then
                                if v then
                                    -- split condition_value_resolved by whitespace
                                    local condition_values = {}
                                    for w in string_gmatch(condition_value_resolved, "%S+") do
                                        table_insert(condition_values, w)
                                    end

                                    local matched = false
                                    for _,cv in pairs(condition_values) do
                                        local fixed_condition_value = string_gsub(cv, "([%^%$%(%)%%%.%[%]%*%+%-%?])", "%%%1")
                                        if string_match(v, "^"..fixed_condition_value.."$") then
                                            matched = true
                                        end
                                    end

                                    if not matched then
                                        --debug("---- CONDITION MATCHED ".. conditions_matched .." ----> op:"..condition.op.." v:"..v.." condition_value:" .. condition_value_resolved)
                                        increment_condition_matched = true
                                        --table_insert(kong.ctx.plugin.rule_matched_parts, { ["matched_on"] = k, ["matched_value"] = v })
                                    end
                                end
                            end

                            -- pm (case insensitive match words)
                            if condition.op == "pm" then
                                -- split condition_value_resolved by whitespace
                                local condition_values = {}
                                for w in string_gmatch(condition_value_resolved, "%S+") do
                                    table_insert(condition_values, w)
                                end
                                for _,cv in pairs(condition_values) do
                                    -- prepend % to special characters in condition_value_resolved
                                    local safe_condition_value = string_gsub(cv, "([%^%$%(%)%%%.%[%]%*%+%-%?])", "%%%1")
                                    --debug("Trying to match: "..v:lower().." with "..safe_condition_value:lower())
                                    if string_match(v:lower(), safe_condition_value:lower()) then
                                        --debug("---- CONDITION MATCHED ".. conditions_matched .." ----> op:"..condition.op.." v:"..v.." condition_value:" .. condition_value_resolved)
                                        increment_condition_matched = true
                                        table_insert(kong.ctx.plugin.rule_matched_parts, { ["matched_on"] = k, ["matched_value"] = v })
                                    end
                                end
                            end

                            -- !pm (case insensitive match words)
                            if condition.op == "!pm" then
                                local not_matched = true

                                -- split condition_value_resolved by whitespace
                                local condition_values = {}
                                for w in string_gmatch(condition_value_resolved, "%S+") do
                                    table_insert(condition_values, w)
                                end
                                for _,cv in pairs(condition_values) do
                                    -- prepend % to special characters in condition_value_resolved
                                    local safe_condition_value = string_gsub(cv, "([%^%$%(%)%%%.%[%]%*%+%-%?])", "%%%1")
                                    --debug("Trying to match: "..v:lower().." with "..safe_condition_value:lower())
                                    if string_match(v:lower(), safe_condition_value:lower()) then
                                        not_matched = false
                                    end
                                end

                                if not_matched then
                                    --debug("---- CONDITION MATCHED ".. conditions_matched .." ----> op:"..condition.op.." v:"..v.." condition_value:" .. condition_value_resolved)
                                    increment_condition_matched = true
                                    table_insert(kong.ctx.plugin.rule_matched_parts, { ["matched_on"] = k, ["matched_value"] = v })
                                end
                            end

                            -- pmFromFile
                            if condition.op == "pmFromFile" then
                                --local dfile = ka_rules:get("ka_dfile_" .. condition_value_resolved)
                                if ka_dfiles and ka_dfiles[condition_value_resolved] then
                                    for _,dvalue in pairs(ka_dfiles[condition_value_resolved]) do
                                        --local safe_condition_value = string_gsub(dvalue, "([%^%$%(%)%%%.%[%]%*%+%-%?])", "%%%1")
                                        local safe_condition_value = dvalue
                                        --debug("Trying to match: "..v:lower().." with "..safe_condition_value:lower())
                                        if string_match(v:lower(), safe_condition_value:lower()) then
                                            --debug("---- CONDITION MATCHED ".. conditions_matched .." ----> op:"..condition.op.." v:"..v.." condition_value:" .. condition_value_resolved)
                                            increment_condition_matched = true
                                            table_insert(kong.ctx.plugin.rule_matched_parts, { ["matched_on"] = k, ["matched_value"] = v })
                                        end
                                    end
                                else
                                    debug("DFile not found: "..condition_value_resolved)
                                end
                            end

                            -- libinjection_xss
                            -- local isxss = libinjection.xss(string)
                            if condition.op == "libinjection_xss" then
                                local isxss = libinjection.xss(v)
                                if isxss then
                                    --debug("---- CONDITION MATCHED ".. conditions_matched .." ----> op:"..condition.op.." v:"..v.." condition_value:" .. condition_value_resolved)
                                    increment_condition_matched = true
                                    table_insert(kong.ctx.plugin.rule_matched_parts, { ["matched_on"] = k, ["matched_value"] = v })
                                end
                            end

                            -- libinjection_sqli
                            -- local issqli = libinjection.sqli(string)
                            if condition.op == "libinjection_sqli" then
                                local issqli = libinjection.sqli(v)
                                if issqli then
                                    --debug("---- CONDITION MATCHED ".. conditions_matched .." ----> op:"..condition.op.." v:"..v.." condition_value:" .. condition_value_resolved)
                                    increment_condition_matched = true
                                    table_insert(kong.ctx.plugin.rule_matched_parts, { ["matched_on"] = k, ["matched_value"] = v })
                                end
                            end

                            -- mcp_method_in: glob match v against space-separated patterns
                            -- (literal | "tools/*" | "notifications/**").
                            if condition.op == "mcp_method_in" then
                                local patterns = {}
                                for w in string_gmatch(tostring(condition_value_resolved or ""), "%S+") do
                                    table_insert(patterns, w)
                                end
                                if v and ka_mcp._method_matches(tostring(v), patterns) then
                                    increment_condition_matched = true
                                    table_insert(kong.ctx.plugin.rule_matched_parts, { ["matched_on"] = k, ["matched_value"] = v })
                                end
                            end

                            -- mcp_jsonrpc_valid: matches when the envelope is INVALID.
                            -- Variable selection is irrelevant; the operator inspects the raw body
                            -- captured by ka_mcp.parse_request().
                            if condition.op == "mcp_jsonrpc_valid" then
                                local mcp = kong.ctx.plugin.mcp
                                if mcp and mcp._raw then
                                    local decoded = cjson_safe.decode(mcp._raw)
                                    local ok = decoded and ka_mcp._validate_jsonrpc(decoded)
                                    if not ok then
                                        increment_condition_matched = true
                                        table_insert(kong.ctx.plugin.rule_matched_parts, { ["matched_on"] = k, ["matched_value"] = "invalid_envelope" })
                                    end
                                end
                            end

                            -- validateUrlEncoding
                            if condition.op == "validateUrlEncoding" then
                                local percent_found_in_value = string_match(v, "%%")
                                -- if % is found in value, and % is not followed by 2 hex characters, then match
                                if percent_found_in_value then
                                    --local m = ngx_re_match(v, "%%[0-9a-fA-F]{2,2}", "s")
                                    if not string_match(v, "%%[0-9a-fA-F][0-9a-fA-F]") then
                                        --debug("---- CONDITION MATCHED ".. conditions_matched .." ----> op:"..condition.op.." v:"..v.." condition_value:" .. condition_value_resolved)
                                        increment_condition_matched = true
                                        table_insert(kong.ctx.plugin.rule_matched_parts, { ["matched_on"] = k, ["matched_value"] = v })
                                    end
                                end
                            end

                            --[[
                                validateByteRange
                                Description: Validates that the byte values used in input 
                                fall into the range specified by the operator parameter. 
                                This operator matches on an input value that contains bytes 
                                that are not in the specified range.

                                example:
                                validateByteRange 10, 13, 32-126
                                validateByteRange 1-255
                            ]]--
                            if condition.op == "validateByteRange" then
                                local allowed_bytes_number = {}
                                local string_to_match = "This is an english sentence."
                                local string_bytes_allowed = true

                                for w in string_gmatch(condition_value_resolved, "[0-9-]+") do
                                    if string_match(w, "-") then
                                        local start_range, end_range = string_match(w, "(%d+)-(%d+)")
                                        for i = start_range, end_range do
                                            -- remove .0 from i
                                            i = string_match(i, "(%d+)")
                                            table_insert(allowed_bytes_number, i)
                                        end
                                    else
                                        table_insert(allowed_bytes_number, w)
                                    end
                                end

                                local function is_byte_allowed(allowed_bytes_number, byte)
                                    for _,allowed_byte in ipairs(allowed_bytes_number) do
                                        if tostring(byte) == tostring(allowed_byte) then
                                            return true
                                        end
                                    end
                                    return false
                                end

                                for i = 1, #v do
                                    local byte = string.byte(v, i)
                                    if not is_byte_allowed(allowed_bytes_number, byte) then
                                        --debug("Byte not allowed: " .. tostring(byte) .. " at position: " .. tostring(i))
                                        string_bytes_allowed = false
                                        break
                                    end
                                end

                                if not string_bytes_allowed then
                                    --debug("---- CONDITION MATCHED ".. conditions_matched .." ----> op:"..condition.op.." v:"..v.." condition_value:" .. condition_value_resolved)
                                    increment_condition_matched = true
                                    table_insert(kong.ctx.plugin.rule_matched_parts, { ["matched_on"] = k, ["matched_value"] = v })
                                end
                            end -- end validateByteRange

                        end -- end if not k_filtered_by_rule_control

                        --debug("Rule matched parts contains "..tostring(#kong.ctx.plugin.rule_matched_parts).." elements for rule id "..rule.id)
                    end
                        
                end
            end
        end

        if increment_condition_matched then
            conditions_matched = conditions_matched + 1
        else
            kong.log.err("|STOP ruleid: ".. rule.id .."| breaking loop condition match, because a condition not matched")
            break
        end

    end



    --debug("Conditions matched: "..conditions_matched.." of "..conditions_to_match)
    --debug("-------------------- END Condition -------------------")

    if conditions_matched >= conditions_to_match then
        if rule.log then
            inspect(rule)
            inspect(kong.ctx.plugin.rule_matched_parts)
        end
        --inspect(kong.ctx.plugin.rule_matched_parts)
        return true, kong.ctx.plugin.rule_matched_parts
    end

    --return false, kong.ctx.plugin.rule_matched_parts, action
    return false, kong.ctx.plugin.rule_matched_parts
end
]==]--

_M.method_allowed = function (self, plugin_conf)
    local request_method = request_get_method()

    local request_method_allowed = false
    for _,method in pairs(plugin_conf.request_methods_allowed) do
        if method == request_method then
            request_method_allowed = true
        end
    end

    if not request_method_allowed then
        table_insert(kong.ctx.plugin.ka_matched_rules, {
            rule = {
                id = "method_allowed",
                log = true,
                logdata = "",
                message = "Request method not allowed",
                phase = "access",
                tags = { "karna", "access", "paranoia-level/1" },
                response_status_override = 405
            },
            part = {
                {
                    matched_on = "request.method",
                    matched_value = request_method
                }
            }
        })

        if plugin_conf.engine_blocking_mode then
            return kong.response.exit(
                405,
                "Method Not Allowed",
                {
                    ["content-type"] = "text/plain",
                    ["cache-control"] = "max-age=0, private, no-store, no-cache, must-revalidate"
                }
            )
        end
    end
end




--[[
    RULE CONTROL FUNCTIONS
    rule_controls_table = {
        ids = {
            <ruleid> = {
                action = "remove"
            },
            <ruleidw> = {
                action = "remove_variables"
                variables = ["request.query.value:pippo"]
            },
        },
        tags = {
            <tag> = {
                action = "remove_target"
                target = ["request.query.value:pippo"]
            }
        },
        remove_target_from_all_rules = {
            "request.query.value:pippo",
            "request.query.value:pluto",
            "request.query.value:paperino"
        }
    }
]]--
_M.__rule_control_rule_removed = function(self, rule)
    if kong.ctx and kong.ctx.plugin then
        if kong.ctx.plugin.rule_controls then
            if kong.ctx.plugin.rule_controls.ids then
                if kong.ctx.plugin.rule_controls.ids[rule.id] then
                    if kong.ctx.plugin.rule_controls.ids[rule.id]["action"] then
                        if kong.ctx.plugin.rule_controls.ids[rule.id]["action"] == "remove" then
                            return true
                        end
                    end
                end
            end
        end
    end
    return false
end
_M.__rule_control_remove_target = function(self, rule)
    if kong.ctx and kong.ctx.plugin then
        if kong.ctx.plugin.rule_controls then
            if kong.ctx.plugin.rule_controls.tags then
                -- rule.tags -> table with all rule's tags
                -- TODO: IMPLEMENT A WAY TO REMOVE FROM TAGS
                -- 
                -- change the "expected" behavior on OWASP_CRS
                -- cause it means "remove all rules" and not remove that tag!
                -- that's stupid and consume a lot of CPU instead of having
                -- remove_all_rules meaning remove this <target variable> from all rules
            end
        end
    end
end


-- OLD
_M.__evaluate_rule_control = function(self, rules, local_rules, plugin_conf)

    debug("__evaluate_rule_control: start")
    for rindex,rule in pairs(local_rules) do
        --inspect(rule)
        local evaluate_rule_control = false
        local rule_control_table = {}

        if rule.plugin_schema_field_name and rule.plugin_schema_field_value then
            --debug("__evaluate_rule_control: evaluating plugin schema field for rule: " .. rule.id)
            if plugin_conf then
                debug("__evaluate_rule_control: plugin_conf is not nil")
                --inspect(plugin_conf)
                --if plugin_conf[local_rules.plugin_schema_field_name] then
                    --debug("__evaluate_rule_control: plugin schema field found in plugin_conf")
                    if tostring(plugin_conf[rule.plugin_schema_field_name]) ~= rule.plugin_schema_field_value then
                        --debug("__evaluate_rule_control: plugin schema field value does not match")
                        --debug("__evaluate_rule_control: plugin_value:".. tostring(plugin_conf[local_rules.plugin_schema_field_name]) .. " expected_value:".. rule.plugin_schema_field_value)
                        goto continue
                    end
                --end
            end
        end

        if rule.rule_control then
            --debug("__evaluate_rule_control: evaluating rule control for rule: " .. rule.id)
            local rule_matched, matched_parts = self:__match_rule_conditions(rule)
            if rule_matched then
                --debug("__evaluate_rule_control: rule matched: " .. rule.id)
                evaluate_rule_control = true
                rule_control_table = rule.rule_control
            end
        end

        if rule.unconditional_match_rule_control then
            debug("__evaluate_rule_control: evaluating unconditional rule control for rule: " .. rule.id)
            evaluate_rule_control = true
            rule_control_table = rule.unconditional_match_rule_control
        end

        if evaluate_rule_control then
            --debug("__evaluate_rule_control: executing rule control for rule: " .. rule.id)
            for ruleci,rulec in pairs(rule_control_table) do
                --debug("__evaluate_rule_control: executing rule control item: " .. ruleci)

                -- change rule action
                if rulec.change_rule_action then
                    rules = self:__replace_rule_action(
                        rules,
                        rulec.change_rule_action.rule_id,
                        rulec.change_rule_action.action
                    )
                end

                -- change condition tfunc
                if rulec.change_condition_tfunc then
                    rules = self:__change_condition_tfunc(
                        rules,
                        rulec.change_condition_tfunc.rule_id,
                        rulec.change_condition_tfunc.condition_number,
                        rulec.change_condition_tfunc.new_tfunc
                    )
                end

                -- change condition value
                if rulec.change_condition_value then
                    rules = self:__change_condition_value(
                        rules,
                        rulec.change_condition_value.rule_id,
                        rulec.change_condition_value.condition_number,
                        rulec.change_condition_value.new_value
                    )
                end

                -- change condition variables
                if rulec.change_condition_variables then
                    rules = self:__change_condition_variables(
                        rules,
                        rulec.change_condition_variables.rule_id,
                        rulec.change_condition_variables.condition_number,
                        rulec.change_condition_variables.new_variables
                    )
                end

                -- replace condition
                if rulec.replace_condition then
                    rules = self:__replace_condition(
                        rules,
                        rulec.replace_condition.rule_id,
                        rulec.replace_condition.condition_number,
                        rulec.replace_condition.new_condition
                    )
                end

                -- remove condition
                if rulec.remove_condition then
                    rules = self:__remove_condition(
                        rules,
                        rulec.remove_condition.rule_id,
                        rulec.remove_condition.condition_number
                    )
                end

                -- add condition
                if rulec.add_condition then
                    rules = self:__add_condition(
                        rules,
                        rulec.add_condition.rule_id,
                        rulec.add_condition.condition
                    )
                end

                -- remove rule
                if rulec.remove_rule then
                    rules = self:__remove_rule(
                        rules,
                        rulec.remove_rule.rule_id
                    )
                end

                -- remove variable from rule conditions
                if rulec.remove_variable_from_rule_conditions then
                    debug("--------> Removing variable from rule conditions")
                    rules = self:__remove_variable_from_rule_conditions(
                        rules,
                        rulec.remove_variable_from_rule_conditions.rule_id,
                        rulec.remove_variable_from_rule_conditions.variable_name
                    )
                end

                -- remove rules by tag
                if rulec.remove_rules_by_tag then
                    rules = self:__remove_rules_by_tag(
                        rules,
                        rulec.remove_rules_by_tag.tag
                    )
                end

                -- remove target pattern by id
                if rulec.remove_target_rule_by_pattern then
                    rules = self:__remove_target_rule_by_pattern(
                        rules,
                        rulec.remove_target_rule_by_pattern.rule_id,
                        rulec.remove_target_rule_by_pattern.pattern
                    )
                end

                -- remove rule id by target name
                if rulec.remove_target_rule_by_name then
                    rules = self:__remove_target_rule_by_name(
                        rules,
                        rulec.remove_target_rule_by_name.rule_id,
                        rulec.remove_target_rule_by_name.name
                    )
                end

                -- remove target pattern by tag
                if rulec.remove_target_tag_by_pattern then
                    --debug("--------> Removing target tag by pattern")
                    rules = self:__remove_target_tag_by_pattern(
                        rules,
                        rulec.remove_target_tag_by_pattern.tag,
                        rulec.remove_target_tag_by_pattern.pattern
                    )
                end

                -- remove target rule by tag
                if rulec.remove_target_rule_by_tag then
                    rules = self:__remove_target_rule_by_tag(
                        rules,
                        rulec.remove_target_rule_by_tag.tag,
                        rulec.remove_target_rule_by_tag.name
                    )
                end

            end
        end

        ::continue::
    end

    return rules
end
_M.__replace_rule_action = function(self, rules, rule_id, new_action)
    --[[ 
        Replaces the action of a rule in the given rules table.
        @param  self        The current object.
        @param  rules       The table of rules.
        @param  rule_id     The ID of the rule to be replaced.
        @param  new_action  The new action to be set for the rule.
        @return The updated rules table.
    ]]--
    for _,rule in pairs(rules) do
        if rule.id == rule_id then
            rule.action = new_action
        end
    end
    return rules
end
_M.__change_condition_tfunc = function(self, rules, rule_id, condition_number, new_tfunc)
    --[[ 
        Changes the transformation function of a condition in the given rules table.
        @param  self             The current object.
        @param  rules            The table of rules.
        @param  rule_id          The ID of the rule to be modified.
        @param  condition_number The number of the condition to be modified.
        @param  new_tfunc        The new transformation function to be set for the condition.
        @return The updated rules table.
    ]]--
    for _,rule in pairs(rules) do
        if rule.id == rule_id then
            if rule.conditions[condition_number] then
                rule.conditions[condition_number].transform = new_tfunc
            end
        end
    end
    return rules
end
_M.__change_condition_value = function(self, rules, rule_id, condition_number, new_value)
    --[[ 
        Changes the value of a condition in the given rules table.
        @param  self             The current object.
        @param  rules            The table of rules.
        @param  rule_id          The ID of the rule to be modified.
        @param  condition_number The number of the condition to be modified.
        @param  new_value        The new value to be set for the condition.
        @return The updated rules table.
    ]]--
    for _,rule in pairs(rules) do
        if rule.id == rule_id then
            rule.conditions[condition_number].value = new_value
        end
    end
    return rules
end
_M.__change_condition_variables = function(self, rules, rule_id, condition_number, new_variables)
    --[[ 
        Changes the variables of a condition in the given rules table.
        @param  self             The current object.
        @param  rules            The table of rules.
        @param  rule_id          The ID of the rule to be modified.
        @param  condition_number The number of the condition to be modified.
        @param  new_variables    The new variables to be set for the condition.
        @return The updated rules table.
    ]]--
    for _,rule in pairs(rules) do
        if rule.id == rule_id then
            rule.conditions[condition_number].variables = new_variables
        end
    end
    return rules
end
_M.__replace_condition = function(self, rules, rule_id, condition_number, new_condition)
    --[[ 
        Replaces a condition in the given rules table.
        @param  self             The current object.
        @param  rules            The table of rules.
        @param  rule_id          The ID of the rule to be modified.
        @param  condition_number The number of the condition to be replaced.
        @param  new_condition    The new condition to be set for the rule.
        @return The updated rules table.
    ]]--
    for _,rule in pairs(rules) do
        if rule.id == rule_id then
            rule.conditions[condition_number] = new_condition
        end
    end
    return rules
end
_M.__remove_condition = function(self, rules, rule_id, condition_number)
    --[[ 
        Removes a condition from the given rules table.
        @param  self             The current object.
        @param  rules            The table of rules.
        @param  rule_id          The ID of the rule to be modified.
        @param  condition_number The number of the condition to be removed.
        @return The updated rules table.
    ]]--
    for _,rule in pairs(rules) do
        if rule.id == rule_id then
            table_remove(rule.conditions, condition_number)
        end
    end
    return rules
end
_M.__add_condition = function(self, rules, rule_id, condition)
    --[[ 
        Adds a condition to the given rules table.
        @param  self             The current object.
        @param  rules            The table of rules.
        @param  rule_id          The ID of the rule to be modified.
        @param  condition        The condition to be added to the rule.
        @return The updated rules table.
    ]]--
    for _,rule in pairs(rules) do
        if rule.id == rule_id then
            table_insert(rule.conditions, condition)
        end
    end
    return rules
end
_M.__remove_rule = function(self, rules, rule_id)
    --[[ 
        Removes a rule from the given rules table.
        @param  self             The current object.
        @param  rules            The table of rules.
        @param  rule_id          The ID of the rule to be removed.
        @return The updated rules table.
    ]]--
    for rulenum,rule in pairs(rules) do
        if rule.id == rule_id then
            rules[rulenum] = nil
        end
    end
    return rules
end
_M.__remove_variable_from_rule_conditions = function(self, rules, rule_id, variable_name)
    --[[ 
        Removes a variable from the conditions of a rule in the given rules table.
        @param  self             The current object.
        @param  rules            The table of rules.
        @param  rule_id          The ID of the rule to be modified.
        @param  variable_name    The name of the variable to be removed from the rule.
        @return The updated rules table.
    ]]--
    for _,rule in pairs(rules) do
        if rule.id == rule_id then
            for conditionnum,condition in pairs(rule.conditions) do
                --inspect(condition.variables)
                for varnum,variable in pairs(condition.variables) do
                    if variable == variable_name then
                        rule.conditions[conditionnum].variables[varnum] = nil
                    end
                end
            end
        end
    end
    return rules
end
_M.__remove_rules_by_tag = function(self, rules, tag)
    --[[
        Removes rules from the given rules table that have the specified tag.
        @param  self             The current object.
        @param  rules            The table of rules.
        @param  tag              The tag to be used to remove rules.
        @return The updated rules table.
    ]]--
    for table_index,rule in pairs(rules) do
        if rule.tags then
            for _,rule_tag in pairs(rule.tags) do
                if rule_tag == tag then
                    rules[table_index] = nil
                end
            end
        end
    end
    return rules
end
_M.__remove_target_rule_by_pattern = function(self, rules, rule_id, pattern)
    --[[
        Removes a target rule from the given rules table by pattern.
        @param  self             The current object.
        @param  rules            The table of rules.
        @param  rule_id          The ID of the rule to be modified.
        @param  pattern          The pattern to be used to remove the target rule.
        @return The updated rules table.
    ]]--
    for _,rule in pairs(rules) do
        if rule.id == rule_id then
            if not rule.rule_control then
                rule.rule_control = {}
            end

            rule.rule_control[#rule.rule_control+1] = {
                remove_target_pattern = pattern
            }
        end
    end
    return rules
end
_M.__remove_target_rule_by_name = function(self, rules, rule_id, name)
    --[[
        Removes a target rule from the given rules table by name.
        @param  self             The current object.
        @param  rules            The table of rules.
        @param  rule_id          The ID of the rule to be modified.
        @param  name             The name to be used to remove the target rule.
        @return The updated rules table.
    ]]--
    for _,rule in pairs(rules) do
        if rule.id == rule_id then
            if not rule.rule_control then
                rule.rule_control = {}
            end

            rule.rule_control[#rule.rule_control+1] = {
                remove_target_name = name
            }
        end
    end
    return rules
end
_M.__remove_target_tag_by_pattern = function(self, rules, tag, pattern)
    --[[ 
        Removes a target tag from the given rules table by pattern.
        @param  self             The current object.
        @param  rules            The table of rules.
        @param  tag              The tag to be used to remove the target tag.
        @param  pattern          The pattern to be used to remove the target tag.
        @return The updated rules table.
    ]]--
    for _,rule in pairs(rules) do
        if rule.tags then
            for _,rule_tag in pairs(rule.tags) do
                if rule_tag == tag then
                    if not rule.rule_control then
                        rule.rule_control = {}
                    end

                    rule.rule_control[#rule.rule_control+1] = {
                        remove_target_pattern = pattern
                    }
                end
            end
        end
    end
    return rules
end
_M.__remove_target_rule_by_tag = function(self, rules, tag, variable_name)
    --[[
        Removes a target rule from the given rules table by tag.
        @param  self             The current object.
        @param  rules            The table of rules.
        @param  tag              The tag to be used to remove the target rule.
        @param  variable_name    The name of the variable to be removed from the rule.
        @return The updated rules table.
    ]]--
    for _,rule in pairs(rules) do
        if rule.tags then
            for _,rule_tag in pairs(rule.tags) do
                if rule_tag == tag then
                    if not rule.rule_control then
                        rule.rule_control = {}
                    end

                    rule.rule_control[#rule.rule_control+1] = {
                        remove_target_name = variable_name
                    }
                end
            end
        end
    end
    return rules
end
-- / RULE CONTROL FUNCTIONS



-- INSPECTION TABLE FUNCTIONS
_M.get_inspection_table = function(self, plugin_conf)
    if not kong.ctx.plugin.inspection_table then
        kong.ctx.plugin.inspection_table = {}
    end

    --[[if plugin_conf then
        for k,v in pairs(plugin_conf) do
            if type(v) == "table" then
                for kk,vv in pairs(v) do
                    table_insert(kong.ctx.plugin.inspection_table, { ["plugin." .. k .. "." .. kk] = tostring(vv) })
                end
            else
                table_insert(kong.ctx.plugin.inspection_table, { ["var:" .. k:lower()] = tostring(v) })
            end
        end
    end]]--

    table_insert(kong.ctx.plugin.inspection_table, {["remote_addr"] = tostring(ngx.var.remote_addr)})

    local phase = get_phase()

    -- set geographic information about source IP (if available)
    if kong.ctx.shared.geoip_country_code then
        table_insert(kong.ctx.plugin.inspection_table, { ["geoip.country_code"] = tostring(kong.ctx.shared.geoip_country_code) })
    end
    if kong.ctx.shared.geoip_country_name then
        table_insert(kong.ctx.plugin.inspection_table, { ["geoip.country_name"] = tostring(kong.ctx.shared.geoip_country_name) })
    end
    if kong.ctx.shared.geoip_continent_code then
        table_insert(kong.ctx.plugin.inspection_table, { ["geoip.continent_code"] = tostring(kong.ctx.shared.geoip_continent_code) })
    end
    if kong.ctx.shared.geoip_continent_name then
        table_insert(kong.ctx.plugin.inspection_table, { ["geoip.continent_name"] = tostring(kong.ctx.shared.geoip_continent_name) })
    end

    -- MCP variables (mcp.transport, mcp.method, mcp.tool.name, mcp.params.*, ...).
    -- Populated only when ka_mcp.detect+parse_request ran in the access phase
    -- (i.e. plugin_conf.mcp_enabled was true and the request matched).
    if plugin_conf and plugin_conf.mcp_enabled and kong.ctx.plugin.mcp then
        ka_mcp.populate_inspection_table(kong.ctx.plugin.inspection_table)
    end

    if phase == "access" then
        local request_raw_path = request_get_raw_path()

        local common_vars = {
            { ["request.method"] = tostring(request_get_method()) },
            { ["request.scheme"] = tostring(request_get_scheme()) },
            { ["request.host"] = tostring(request_get_host()) },
            { ["request.port"] = tostring(request_get_port()) },
            { ["request.forwarded_scheme"] = tostring(request_get_forwarded_scheme()) },
            { ["request.forwarded_host"] = tostring(request_get_forwarded_host()) },
            { ["request.forwarded_port"] = tostring(request_get_forwarded_port()) },
            { ["request.forwarded_path"] = tostring(request_get_forwarded_path()) },
            { ["request.forwarded_prefix"] = tostring(request_get_forwarded_prefix()) },
            { ["request.http_version"] = tostring(request_get_http_version()) },
            { ["request.path"] = tostring(request_get_path()) },
            { ["request.path_with_query"] = tostring(request_get_path_with_query()) },
            { ["request.raw_query"] = tostring(request_raw_path) },
        }

        table_insert(common_vars, { ["request.raw_path"] = tostring(request_raw_path) })

        if plugin_conf.try_bas64decode_if_possible then
            debug("----------------------------------------------------> RAW PATH BASE64 DECODE ATTEMPT: "..request_raw_path)
            -- check if request_raw_path contains string that matches a base64 string
            -- global match and global replace them

            -- remove the first characters if /+
            request_raw_path = string_gsub(request_raw_path, "^/+", "")

            local iterator, err = ngx.re.gmatch(request_raw_path, "([a-zA-Z0-9+/=]{5,})", "s")
            if not iterator then
                debug("Error matching base64: "..err)
            else
                while true do
                    local m, err = iterator()
                    if err then
                        debug("Error matching base64: "..err)
                        break
                    end

                    if not m then
                        break
                    end

                    --request_raw_path = string_gsub(request_raw_path, m[0], <base64decoded>)
                    -- use pcall to catch errors
                    debug("----------------------------------------------------> RAW PATH BASE64 DECODE ATTEMPT: "..m[0])
                    m[0] = string_gsub(m[0], "+", "-")
                    m[0] = string_gsub(m[0], "/", "_")
                    local status, decoded = pcall(b64.decode_base64url, m[0])
                    if status then
                        local decoded_string = tostring(decoded)
                        debug("----------------------------------------------------> RAW PATH BASE64 DECODED: "..decoded_string)
                        -- replace special character with lua pattern escape
                        decoded_string = string_gsub(decoded_string, "([%^%$%(%)%%%.%[%]%*%+%-%?%{%}])", "%%%1")
                        request_raw_path = string_gsub(request_raw_path, m[0], decoded_string)
                        table_insert(common_vars, { ["request.raw_path"] = tostring(request_raw_path) })
                    end
                end
            end
        end

        -- add { ["request.raw_path"] = tostring(request_get_raw_path()) } to common vars
        

        for k,v in pairs(common_vars) do
            table_insert(kong.ctx.plugin.inspection_table, v)
        end

        -- kong.ctx.plugin.rule_variables
        for k,v in pairs(kong.ctx.plugin.rule_variables) do
            table_insert(kong.ctx.plugin.inspection_table, { ["var:"..k] = tostring(v) })
        end

        -- set request line
        local request_line = request_get_method().." "..request_get_path_with_query().." HTTP/"..request_get_http_version()
        table_insert(kong.ctx.plugin.inspection_table, { ["request.line"] = tostring(request_line) })

        -- set basename
        -- get the last part of the raw path without /
        local basename = string_match(request_raw_path, "([^/]+)$")
        if basename then
            table_insert(kong.ctx.plugin.inspection_table, { ["request.basename"] = tostring(basename) })
        else
            table_insert(kong.ctx.plugin.inspection_table, { ["request.basename"] = "" })
        end

        if request_get_raw_query() then
            local query_string = request_get_raw_query()
            local qs_flattened = self:__qs_parser(query_string, plugin_conf.try_bas64decode_if_possible)
            for _,v in pairs(qs_flattened) do
                table_insert(kong.ctx.plugin.inspection_table, v)
            end
        end

        for k,v in pairs(request_get_headers()) do
            local header_name_lowercase = k:lower()
            table_insert(kong.ctx.plugin.inspection_table, { ["request.header.value:"..header_name_lowercase] = v })
            table_insert(kong.ctx.plugin.inspection_table, { ["request.header.name:"..header_name_lowercase] = k })

            -- request.header_no_fp.value:<name>
            -- .*(?:[Uu]ser\\-[Aa]gent|[Rr]eferer|[Aa]ccept.*|[Cc]ontent.*|[Ss]ec\\-|[Aa]uthorization).*
            if
                not string_match(k, "^user%-agent") and
                not string_match(k, "^referer") and
                not string_match(k, "^accept") and
                not string_match(k, "^content") and
                not string_match(k, "^sec%-") and
                not string_match(k, "^authorization")
            then
                table_insert(kong.ctx.plugin.inspection_table, { ["request.header_no_fp.value:"..header_name_lowercase] = v })
            end

            if plugin_conf.try_bas64decode_if_possible then
                debug("                 HEADERS: Trying to base64 decode: "..v)
                if header_name_lowercase ~= "content-type" and header_name_lowercase ~= "content-length" then
                    v = string_gsub(v, "+", "-")
                    v = string_gsub(v, "/", "_")

                    -- replace %3D with =
                    v = string_gsub(v, "%%3[dD]", "=")

                    -- use pcall to catch errors
                    local status, decoded = pcall(b64.decode_base64url, v)
                    if status and decoded then
                        debug("                 HEADERS: Base64 decoded: "..decoded)
                        table_insert(kong.ctx.plugin.inspection_table, { ["request.header.value:"..header_name_lowercase..'_ka_b64_decoded'] = decoded })
                    end
                end
            end
        end

        -- check if request header referer is set
        local referer = request_get_headers()["referer"]
        if referer then
            local parsed_url_referer = utils:url_parser(referer)
            if parsed_url_referer then
                for k,v in pairs(parsed_url_referer) do
                    table_insert(kong.ctx.plugin.inspection_table, {["request.header.referer."..k:lower()] = v})
                end

                if parsed_url_referer.query then
                    local qs_flattened = body_parser:urlencoded("request.header.referer.query", parsed_url_referer.query, plugin_conf.try_bas64decode_if_possible)
                    for k,v in pairs(qs_flattened) do
                        table_insert(kong.ctx.plugin.inspection_table, v)
                    end
                end
            end
        end

        -- check if request header cookie is set
        local cookie = request_get_headers()["cookie"]
        if cookie then
            local cookie_flattened = body_parser:cookie("request.cookie", cookie, plugin_conf.try_bas64decode_if_possible)
            for _,v in pairs(cookie_flattened) do
                --[[local value_is_json = false

                for ckeyn,cval in pairs(v) do
                    if pcall(cjson.decode,cval) then
                        value_is_json = true
                        local cookie_json_flat = body_parser:json("request.cookie", cval, plugin_conf.try_bas64decode_if_possible)
                        for kk,vv in pairs(cookie_json_flat) do
                            table_insert(kong.ctx.plugin.inspection_table, vv)
                        end
                    end
                end
                if not value_is_json then
                    table_insert(kong.ctx.plugin.inspection_table, v)
                end]]--
                table_insert(kong.ctx.plugin.inspection_table, v)
            end
        end

        -- get request body
        local request_body = request_get_raw_body()

        -- if not request_body, but content-length is set, then try to use ngx.req.get_body_file
        -- ngx.req.get_body_file: Retrieves the file name for the in-file request body data. Returns nil if the request body has not been read or has been read into memory.
        if not request_body then
            local content_length = request_get_headers()["content-length"]
            if content_length then
                local body_file = ngx_req_get_body_file()
                if body_file then
                    debug("-> Reading request body from file")
                    local file = io.open(body_file, "r")
                    if file then
                        request_body = file:read("*a")
                        file:close()
                    end
                end
            end
        end

        -- parse request body
        if request_body and request_body ~= "" then
            debug("-> Setting request body to true")
            --inspect(request_body)
            kong.ctx.plugin.request_has_body = true
            table_insert(kong.ctx.plugin.inspection_table, { ["request.body"] = tostring(request_body) })
            table_insert(kong.ctx.plugin.inspection_table, { ["request.body.length"] = tonumber(string_len(request_body)) })

            -- get request body type
            local request_body_type = utils:request_body_parser_type()

            if request_body_type == "json" then
                if pcall(cjson.decode,request_body) then
                    table_insert(kong.ctx.plugin.inspection_table, { ["request.body.processor"] = tostring(request_body_type) })
                    local json_flattened = body_parser:json("request.body.json", request_body, plugin_conf.try_bas64decode_if_possible)
                    for _,v in pairs(json_flattened) do
                        table_insert(kong.ctx.plugin.inspection_table, v)
                    end
                end
            end

            if request_body_type == "xml" then
                table_insert(kong.ctx.plugin.inspection_table, { ["request.body.processor"] = tostring(request_body_type) })
                local xml_flattened = body_parser:xml("request.body.xml", request_body)
                for _,v in pairs(xml_flattened) do
                    table_insert(kong.ctx.plugin.inspection_table, v)
                end
            end

            if request_body_type == "urlencoded" then
                table_insert(kong.ctx.plugin.inspection_table, { ["request.body.processor"] = tostring(request_body_type) })
                local urlencoded_flattened = body_parser:urlencoded("request.body.urlencode", request_body, plugin_conf.try_bas64decode_if_possible)
                inspect(urlencoded_flattened)
                for _,v in pairs(urlencoded_flattened) do
                    table_insert(kong.ctx.plugin.inspection_table, v)
                end
            end

            if request_body_type == "multipart" then
                table_insert(kong.ctx.plugin.inspection_table, { ["request.body.processor"] = tostring(request_body_type) })
                local multipart_flattened = body_parser:multipart("request.body.multipart", request_body, plugin_conf.try_bas64decode_if_possible)
                for _,v in pairs(multipart_flattened) do
                    table_insert(kong.ctx.plugin.inspection_table, v)
                end

                -- gmatch on ^Content-\S+: ([^\r\n]+) and set request.body.multipart.header.<name> = <value>
                local n = 1
                local iterator, err = ngx.re.gmatch(request_body, "^(content\\-\\S+): ([^\\r\\n]+)", "im")
                if not iterator then
                    debug("error: "..err)
                end
                while true do
                    local header = iterator()
                    if not header then
                        break
                    end
                    table_insert(kong.ctx.plugin.inspection_table, { ["request.body.multipart.header.value:."..header[1]:lower()] = header[2] })
                    table_insert(kong.ctx.plugin.inspection_table, { ["request.body.multipart.header.name:."..header[1]:lower()] = header[1] })
                    table_insert(kong.ctx.plugin.inspection_table, { ["request.body.multipart.header.raw."..n] = header[1]..": "..header[2] })
                    n = n + 1
                end
            end
        end
    end

    if phase == "header_filter" then
        -- response status code
        local response_status = response_get_status()
        table_insert(kong.ctx.plugin.inspection_table, { ["response.status"] = tostring(response_status) })

        local response_headers = response_get_headers()
        local set_cookie_values = {}
        for k,v in pairs(response_headers) do
            if type(v) == "table" then
                for kk,vv in pairs(v) do
                    --debug("response header: "..k.." = "..vv)
                    table_insert(kong.ctx.plugin.inspection_table, { ["response.header.value:"..k:lower()] = vv })
                    table_insert(kong.ctx.plugin.inspection_table, { ["response.header.name:"..k:lower()] = k })
                    if k:lower() == "set-cookie" then
                        table_insert(set_cookie_values, vv)
                    end
                end
            else
                --debug("response header: "..k.." = "..v)
                table_insert(kong.ctx.plugin.inspection_table, { ["response.header.value:"..k:lower()] = v })
                table_insert(kong.ctx.plugin.inspection_table, { ["response.header.name:"..k:lower()] = k })
                if k:lower() == "set-cookie" then
                    table_insert(set_cookie_values, v)
                end
            end
        end

        --inspect(set_cookie_values)

        for _,cookie in pairs(set_cookie_values) do
            local cookie_flattened = body_parser:urlencoded("response.set_cookie", cookie, plugin_conf.try_bas64decode_if_possible)
            for k,v in pairs(cookie_flattened) do
                local value_is_json = false

                for ckeyn,cval in pairs(v) do
                    if pcall(cjson.decode,cval) then
                        value_is_json = true
                        local cookie_json_flat = body_parser:json("response.set_cookie", cval, plugin_conf.try_bas64decode_if_possible)
                        for kk,vv in pairs(cookie_json_flat) do
                            table_insert(kong.ctx.plugin.inspection_table, vv)
                        end
                    end
                end
                if not value_is_json then
                    table_insert(kong.ctx.plugin.inspection_table, v)
                end
            end
        end

        --inspect(kong.ctx.plugin.inspection_table)
    end

    if plugin_conf.inspection_table_convert then
        if #plugin_conf.inspection_table_convert > 0 then
            for k,v in pairs(plugin_conf.inspection_table_convert) do
                -- v should contains a json like: {"pattern": "request%.body%.urlencode%.value%:a", "type": "json", "prefix": "request.foo.json"}
                local convert = cjson.decode(v)
                if convert then
                    if convert.pattern and convert.type and convert.prefix then
                        self:convert_inspection_table_value(convert.pattern, convert.type, convert.prefix)
                    end
                end
            end
        end
    end

end

_M.__get_value_from_inspection_table = function(self, pattern, filter_out_pattern)
    local return_table = {}
    if not filter_out_pattern then
        filter_out_pattern = "^$"
    end
    for _,v in pairs(kong.ctx.plugin.inspection_table) do
        for key,_ in pairs(v) do
            if string_match(key, pattern) then
                if not string_match(key, filter_out_pattern) then
                    table_insert(return_table, v)
                end
            end
        end
    end
    return return_table
end

_M.__object_exists_in_rule_inspection_table = function (self, key, value)
    for k,v in pairs(kong.ctx.plugin.rule_inspection_table) do
        if v[key] == value then
            return true
        end
    end
    return false
end

_M.__add_value_to_rule_inspection_table = function(self, tfunc_table, value_table, multi_match_enabled)
    local result_table = {}

    for key_name,value in pairs(value_table) do
        local result_value_table = {}

        -- if value is not a table, convert it to a table
        if type(value) ~= "table" then
            table_insert(result_value_table, value)
        else
            result_value_table = value
        end

        --[[if multi_match_enabled then
            local can_append_on_rule_inspection_table = true
            for k,v in pairs(kong.ctx.plugin.rule_inspection_table) do
                debug("-----------------___> check if v contains key: "..key_name .." --> "..tostring(v[key_name]))
                if v[key_name] then
                    if v[key_name] == result_value then
                        can_append_on_rule_inspection_table = false
                    end
                end
            end
            if can_append_on_rule_inspection_table then
                table_insert(kong.ctx.plugin.rule_inspection_table, {[key_name] = result_value})
            end
        end]]--

        for _,result_value in pairs(result_value_table) do
            if tfunc_table then
                for _,tfunc in pairs(tfunc_table) do
                    --inspect(result_value)
                    --debug("Applying transformation function: "..tfunc.." to value: "..result_value)
                    result_value = self:__apply_transformation(tfunc, result_value)
                    if multi_match_enabled then
                        local obj_already_exists = false
                        for k,v in pairs(kong.ctx.plugin.rule_inspection_table) do
                            if v[key_name] == result_value then
                                obj_already_exists = true
                            end
                        end
                        if not obj_already_exists then
                            -- debug("++++++++++ Adding to rule_inspection_table: "..key_name.." -> "..result_value)
                            table_insert(kong.ctx.plugin.rule_inspection_table, {[key_name] = result_value})
                            table_insert(result_table, {[key_name] = result_value})
                        end
                    end
                    -- debug("Result value: "..result_value)
                end
            end

            if not multi_match_enabled then
                if not self:__object_exists_in_rule_inspection_table(key_name, result_value) then
                    -- debug("++++++++++ Adding to rule_inspection_table: "..key_name.." -> "..result_value)
                    table_insert(kong.ctx.plugin.rule_inspection_table, {[key_name] = result_value})
                    table_insert(result_table, {[key_name] = result_value})
                end
            end
        end
    end
    return result_table
end

_M.__set_rule_inspection_table = function(self, rule, condition, plugin_conf)
    kong.ctx.plugin.rule_inspection_table = {}
    if not kong.ctx.plugin.rule_inspection_table_cache then
        kong.ctx.plugin.rule_inspection_table_cache = {}
        kong.log.err("rule_inspection_table_cache is nil")
    end

    local multi_match_enabled = false
    if condition.multi_match then
        multi_match_enabled = true
    end

    if condition.variables then
        for _,variable in pairs(condition.variables) do
            local cache_key = variable .. table.concat(condition.transform, ",") .. tostring(multi_match_enabled)
            kong.log.err("cache_key: "..cache_key)

            if variable == "request.arg.value" then

                if not kong.ctx.plugin.rule_inspection_table_cache[cache_key] then
                    kong.ctx.plugin.rule_inspection_table_cache[cache_key] = {}
                    for _,v in pairs(self:__get_value_from_inspection_table("^request%.query%.value%:")) do
                        local value_table = self:__add_value_to_rule_inspection_table(condition.transform, v, multi_match_enabled)
                        for _,vcache in pairs(value_table) do
                            table_insert(kong.ctx.plugin.rule_inspection_table_cache[cache_key], vcache)
                        end
                    end

                    for _,v in pairs(self:__get_value_from_inspection_table("^request%.body%..+%.value%:", "^request%.body%.multipart%.header")) do
                        local value_table = self:__add_value_to_rule_inspection_table(condition.transform, v, multi_match_enabled)
                        for _,vcache in pairs(value_table) do
                            table_insert(kong.ctx.plugin.rule_inspection_table_cache[cache_key], vcache)
                        end
                    end

                    for _,v in pairs(self:__get_value_from_inspection_table("^request%.body%.xml%.value%.%d+")) do
                        local value_table = self:__add_value_to_rule_inspection_table(condition.transform, v, multi_match_enabled)
                        for _,vcache in pairs(value_table) do
                            table_insert(kong.ctx.plugin.rule_inspection_table_cache[cache_key], vcache)
                        end
                    end
                else
                    --debug("-----------------> Using cache for request.arg.value")
                    for _,v in pairs(kong.ctx.plugin.rule_inspection_table_cache[cache_key]) do
                        table_insert(kong.ctx.plugin.rule_inspection_table, v)
                    end
                end

            elseif variable == "request.arg.name" then

                if not kong.ctx.plugin.rule_inspection_table_cache[cache_key] then
                    kong.ctx.plugin.rule_inspection_table_cache[cache_key] = {}

                    for _,v in pairs(self:__get_value_from_inspection_table("^request%.query%.name%:")) do
                        local value_table = self:__add_value_to_rule_inspection_table(condition.transform, v, multi_match_enabled)
                        for _,vcache in pairs(value_table) do
                            table_insert(kong.ctx.plugin.rule_inspection_table_cache[cache_key], vcache)
                        end
                    end

                    for _,v in pairs(self:__get_value_from_inspection_table("^request%.body%..+%.name%:", "^request%.body%.multipart%.header")) do
                        local value_table = self:__add_value_to_rule_inspection_table(condition.transform, v, multi_match_enabled)
                        for _,vcache in pairs(value_table) do
                            table_insert(kong.ctx.plugin.rule_inspection_table_cache[cache_key], vcache)
                        end
                    end

                    --[[for _,v in pairs(self:__get_value_from_inspection_table("^request%.body%.xml%.name%.%d+")) do
                        self:__add_value_to_rule_inspection_table(condition.transform, v, multi_match_enabled)
                    end]]--
                else
                    --debug("-----------------> Using cache for request.arg.name")
                    for _,v in pairs(kong.ctx.plugin.rule_inspection_table_cache[cache_key]) do
                        table_insert(kong.ctx.plugin.rule_inspection_table, v)
                    end
                end

            elseif variable == "request.query.name" then
                
                if not kong.ctx.plugin.rule_inspection_table_cache[cache_key] then
                    kong.ctx.plugin.rule_inspection_table_cache[cache_key] = {}

                    for _,v in pairs(self:__get_value_from_inspection_table("^request%.query%.name%:")) do
                        local value_table = self:__add_value_to_rule_inspection_table(condition.transform, v, multi_match_enabled)
                        for _,vcache in pairs(value_table) do
                            table_insert(kong.ctx.plugin.rule_inspection_table_cache[cache_key], vcache)
                        end
                    end
                else
                    --debug("-----------------> Using cache for request.query.name")
                    for _,v in pairs(kong.ctx.plugin.rule_inspection_table_cache[cache_key]) do
                        table_insert(kong.ctx.plugin.rule_inspection_table, v)
                    end
                end
            
            elseif variable == "request.arg.combined_size" then

                if not kong.ctx.plugin.rule_inspection_table_cache[cache_key] then
                    kong.ctx.plugin.rule_inspection_table_cache[cache_key] = {}

                    local combined_size = 0
                    --debug("Combined Size: " .. tostring(combined_size))
                    for _,v in pairs(self:__get_value_from_inspection_table("^request%.query%.value%:")) do
                        for _,vv in pairs(v) do
                            combined_size = (combined_size+#vv)
                            --debug("Combined Size (adding " .. tostring(#vv) .. " / ".. vv .."): " .. tostring(combined_size))
                        end
                    end
                    for _,v in pairs(self:__get_value_from_inspection_table("^request%.body%..+%.value%:")) do
                        for _,vv in pairs(v) do
                            combined_size = (combined_size+#vv)
                            --debug("Combined Size (adding " .. tostring(#vv) .. " / ".. vv .."): " .. tostring(combined_size))
                        end
                    end
                    --debug("FINAL Combined Size: " .. tostring(combined_size))
                    local value_table = self:__add_value_to_rule_inspection_table(condition.transform, {["request.arg.combined_size"] = combined_size}, multi_match_enabled)
                    for _,vcache in pairs(value_table) do
                        table_insert(kong.ctx.plugin.rule_inspection_table_cache[cache_key], vcache)
                    end
                else
                    --debug("-----------------> Using cache for request.arg.combined_size")
                    for _,v in pairs(kong.ctx.plugin.rule_inspection_table_cache[cache_key]) do
                        table_insert(kong.ctx.plugin.rule_inspection_table, v)
                    end
                end

            elseif variable == "combined_file_sizes" then

                if not kong.ctx.plugin.rule_inspection_table_cache[cache_key] then
                    kong.ctx.plugin.rule_inspection_table_cache[cache_key] = {}

                    local combined_size = 0
                    for _,v in pairs(self:__get_value_from_inspection_table("^request%.body%.multipart%.filename%:")) do
                        for kk,vv in pairs(v) do
                            combined_size = (combined_size+#vv)
                        end
                    end
                    local value_table = self:__add_value_to_rule_inspection_table(condition.transform, {["combined_file_sizes"] = combined_size}, multi_match_enabled)
                    for _,vcache in pairs(value_table) do
                        table_insert(kong.ctx.plugin.rule_inspection_table_cache[cache_key], vcache)
                    end
                else
                    --debug("-----------------> Using cache for combined_file_sizes")
                    for _,v in pairs(kong.ctx.plugin.rule_inspection_table_cache[cache_key]) do
                        table_insert(kong.ctx.plugin.rule_inspection_table, v)
                    end
                end

            elseif variable == "request.query.value" then

                if not kong.ctx.plugin.rule_inspection_table_cache[cache_key] then
                    kong.ctx.plugin.rule_inspection_table_cache[cache_key] = {}
                    for _,v in pairs(self:__get_value_from_inspection_table("^request%.query%.value%:")) do
                        -- table_insert(kong.ctx.plugin.rule_inspection_table, v)
                        local value_table = self:__add_value_to_rule_inspection_table(condition.transform, v, multi_match_enabled)
                        for _,vcache in pairs(value_table) do
                            table_insert(kong.ctx.plugin.rule_inspection_table_cache[cache_key], vcache)
                        end
                    end
                else
                    --debug("-----------------> Using cache for request.query.value")
                    for _,v in pairs(kong.ctx.plugin.rule_inspection_table_cache[cache_key]) do
                        table_insert(kong.ctx.plugin.rule_inspection_table, v)
                    end
                end

            elseif variable == "request.cookie.value" then

                if not kong.ctx.plugin.rule_inspection_table_cache[cache_key] then
                    kong.ctx.plugin.rule_inspection_table_cache[cache_key] = {}
                    for _,v in pairs(self:__get_value_from_inspection_table("^request%.cookie%.value%:")) do
                        local value_table = self:__add_value_to_rule_inspection_table(condition.transform, v, multi_match_enabled)
                        for _,vcache in pairs(value_table) do
                            table_insert(kong.ctx.plugin.rule_inspection_table_cache[cache_key], vcache)
                        end
                    end
                else
                    --debug("-----------------> Using cache for request.cookie.value")
                    for _,v in pairs(kong.ctx.plugin.rule_inspection_table_cache[cache_key]) do
                        table_insert(kong.ctx.plugin.rule_inspection_table, v)
                    end
                end
            
            elseif variable == "request.cookie.name" then

                if not kong.ctx.plugin.rule_inspection_table_cache[cache_key] then
                    kong.ctx.plugin.rule_inspection_table_cache[cache_key] = {}
                    for _,v in pairs(self:__get_value_from_inspection_table("^request%.cookie%.name%:")) do
                        local value_table = self:__add_value_to_rule_inspection_table(condition.transform, v, multi_match_enabled)
                        for _,vcache in pairs(value_table) do
                            table_insert(kong.ctx.plugin.rule_inspection_table_cache[cache_key], vcache)
                        end
                    end
                else
                    --debug("-----------------> Using cache for request.cookie.name")
                    for _,v in pairs(kong.ctx.plugin.rule_inspection_table_cache[cache_key]) do
                        table_insert(kong.ctx.plugin.rule_inspection_table, v)
                    end
                end

            elseif variable == "request.header.value" then
                
                if not kong.ctx.plugin.rule_inspection_table_cache[cache_key] then
                    kong.ctx.plugin.rule_inspection_table_cache[cache_key] = {}
                    for _,v in pairs(self:__get_value_from_inspection_table("^request%.header%.value%:")) do
                        local value_table = self:__add_value_to_rule_inspection_table(condition.transform, v, multi_match_enabled)
                        for _,vcache in pairs(value_table) do
                            table_insert(kong.ctx.plugin.rule_inspection_table_cache[cache_key], vcache)
                        end
                    end
                else
                    --debug("-----------------> Using cache for request.header.value")
                    for _,v in pairs(kong.ctx.plugin.rule_inspection_table_cache[cache_key]) do
                        table_insert(kong.ctx.plugin.rule_inspection_table, v)
                    end
                end

            elseif variable == "request.header.name" then

                if not kong.ctx.plugin.rule_inspection_table_cache[cache_key] then
                    kong.ctx.plugin.rule_inspection_table_cache[cache_key] = {}
                    for _,v in pairs(self:__get_value_from_inspection_table("^request%.header%.name%:")) do
                        local value_table = self:__add_value_to_rule_inspection_table(condition.transform, v, multi_match_enabled)
                        for _,vcache in pairs(value_table) do
                            table_insert(kong.ctx.plugin.rule_inspection_table_cache[cache_key], vcache)
                        end
                    end
                else
                    --debug("-----------------> Using cache for request.header.name")
                    for _,v in pairs(kong.ctx.plugin.rule_inspection_table_cache[cache_key]) do
                        table_insert(kong.ctx.plugin.rule_inspection_table, v)
                    end
                end
            
            elseif variable == "request.header_no_fp.value" then

                if not kong.ctx.plugin.rule_inspection_table_cache[cache_key] then
                    kong.ctx.plugin.rule_inspection_table_cache[cache_key] = {}
                    for _,v in pairs(self:__get_value_from_inspection_table("^request%.header%_no%_fp%.value%:")) do
                        local value_table = self:__add_value_to_rule_inspection_table(condition.transform, v, multi_match_enabled)
                        for _,vcache in pairs(value_table) do
                            table_insert(kong.ctx.plugin.rule_inspection_table_cache[cache_key], vcache)
                        end
                    end
                else
                    --debug("-----------------> Using cache for request.header_no_fp.value")
                    for _,v in pairs(kong.ctx.plugin.rule_inspection_table_cache[cache_key]) do
                        table_insert(kong.ctx.plugin.rule_inspection_table, v)
                    end
                end

            elseif variable == "request.body.multipart.header.value" then
                
                for _,v in pairs(self:__get_value_from_inspection_table("^request%.body%.multipart%.header%.value%:")) do
                    self:__add_value_to_rule_inspection_table(condition.transform, v, multi_match_enabled)
                end
            
            -- request.body.multipart.header.raw
            elseif variable == "request.body.multipart.header.raw" then
                
                for _,v in pairs(self:__get_value_from_inspection_table("^request%.body%.multipart%.header%.raw")) do
                    self:__add_value_to_rule_inspection_table(condition.transform, v, multi_match_enabled)
                end
                
            elseif variable == "matched.value" then

                if not kong.ctx.plugin.rule_inspection_table_cache[cache_key] then
                    kong.ctx.plugin.rule_inspection_table_cache[cache_key] = {}
                    for _,v in pairs(kong.ctx.plugin.rule_matched_parts) do
                        if v.matched_on and v.matched_on ~= "var:paranoia_level" then
                            for kk,vv in pairs(v) do
                                if kk == "matched_value" then
                                    local value_table = self:__add_value_to_rule_inspection_table(condition.transform, {[kk] = vv}, multi_match_enabled)
                                    for _,vcache in pairs(value_table) do
                                        table_insert(kong.ctx.plugin.rule_inspection_table_cache[cache_key], vcache)
                                    end
                                end
                            end
                        end
                    end
                else
                    --debug("-----------------> Using cache for matched.value")
                    for _,v in pairs(kong.ctx.plugin.rule_inspection_table_cache[cache_key]) do
                        table_insert(kong.ctx.plugin.rule_inspection_table, v)
                    end
                end

            elseif string_match(variable, "^group:") then

                if not kong.ctx.plugin.rule_inspection_table_cache[cache_key] then
                    kong.ctx.plugin.rule_inspection_table_cache[cache_key] = {}
                    local group_number = tonumber(string_match(variable, "^group:(%d+)"))
                    if group_number then
                        for _,v in pairs(kong.ctx.plugin.rule_matched_parts) do
                            if v["matched_group_"..group_number] then
                                local value_table = self:__add_value_to_rule_inspection_table(
                                    condition.transform,
                                    {
                                        ["matched_group_"..group_number] = v["matched_group_"..group_number]
                                    },
                                    multi_match_enabled
                                )
                                for _,vcache in pairs(value_table) do
                                    table_insert(kong.ctx.plugin.rule_inspection_table_cache[cache_key], vcache)
                                end
                            end
                        end
                    end
                else
                    --debug("-----------------> Using cache for group:")
                    for _,v in pairs(kong.ctx.plugin.rule_inspection_table_cache[cache_key]) do
                        table_insert(kong.ctx.plugin.rule_inspection_table, v)
                    end
                end

            elseif variable == "request.file" then

                if not kong.ctx.plugin.rule_inspection_table_cache[cache_key] then
                    for _,v in pairs(self:__get_value_from_inspection_table("^request%.body%.multipart%.filename")) do
                        local value_table = self:__add_value_to_rule_inspection_table(condition.transform, v, multi_match_enabled)
                        for _,vcache in pairs(value_table) do
                            table_insert(kong.ctx.plugin.rule_inspection_table_cache[cache_key], vcache)
                        end
                    end

                    for _,v in pairs(self:__get_value_from_inspection_table("^request%.body%.multipart%.name")) do
                        local value_table = self:__add_value_to_rule_inspection_table(condition.transform, v, multi_match_enabled)
                        for _,vcache in pairs(value_table) do
                            table_insert(kong.ctx.plugin.rule_inspection_table_cache[cache_key], vcache)
                        end
                    end
                else
                    --debug("-----------------> Using cache for request.file")
                    for _,v in pairs(kong.ctx.plugin.rule_inspection_table_cache[cache_key]) do
                        table_insert(kong.ctx.plugin.rule_inspection_table, v)
                    end
                end

            elseif variable == "request.body.processor" then
                local body_parser_type = utils:request_body_parser_type()
                self:__add_value_to_rule_inspection_table(condition.transform, {["request.body.processor"] = body_parser_type}, multi_match_enabled)
            elseif variable == "request.raw_body_if_type_unknown" then
                local body_parser_type = utils:request_body_parser_type()
                if body_parser_type == "text" then
                    for _,v in pairs(self:__get_value_from_inspection_table("^request%.body$")) do
                        self:__add_value_to_rule_inspection_table(condition.transform, {["request.raw_body_if_type_unknown"] = v["request.body"]}, multi_match_enabled)
                    end
                end
            elseif variable == "response.header.value" then
                
                if not kong.ctx.plugin.rule_inspection_table_cache[cache_key] then
                    kong.ctx.plugin.rule_inspection_table_cache[cache_key] = {}
                    for _,v in pairs(self:__get_value_from_inspection_table("^response%.header%.value%:")) do
                        local value_table = self:__add_value_to_rule_inspection_table(condition.transform, v, multi_match_enabled)
                    end
                else
                    --debug("-----------------> Using cache for response.header.value")
                    for _,v in pairs(kong.ctx.plugin.rule_inspection_table_cache[cache_key]) do
                        table_insert(kong.ctx.plugin.rule_inspection_table, v)
                    end
                end

            elseif variable == "response.header.name" then

                if not kong.ctx.plugin.rule_inspection_table_cache[cache_key] then
                    kong.ctx.plugin.rule_inspection_table_cache[cache_key] = {}
                    for _,v in pairs(self:__get_value_from_inspection_table("^response%.header%.name%:")) do
                        local value_table = self:__add_value_to_rule_inspection_table(condition.transform, v, multi_match_enabled)
                    end
                else
                    --debug("-----------------> Using cache for response.header.name")
                    for _,v in pairs(kong.ctx.plugin.rule_inspection_table_cache[cache_key]) do
                        table_insert(kong.ctx.plugin.rule_inspection_table, v)
                    end
                end

            elseif string_match(variable, "^redis%.key:") then
                debug("############################# REDIS KEY FOUND on variable list")
                utils.redis_host = plugin_conf.redis_host
                utils.redis_port = plugin_conf.redis_port
                utils.redis_password = plugin_conf.redis_password
                
                local redis_client = utils:redis_connect()
                if redis_client then
                    local redis_key_name_raw = string_match(variable, "^redis%.key:(.+)")
                    local redis_key_name = self:replace_variable_in_string(redis_key_name_raw)
                    debug("Redis key name to inspect: "..redis_key_name)
                    local redis_key_value = redis_client:get(redis_key_name)
                    if redis_key_value ~= ngx.null then
                        self:__add_value_to_rule_inspection_table(condition.transform, {[redis_key_name_raw] = redis_key_value}, multi_match_enabled)
                    end
                else
                    debug("######################> Redis client not available")
                end
            end

            for _,v in pairs(kong.ctx.plugin.inspection_table) do
                for key,_ in pairs(v) do
                    if key == string_lower(variable) then
                        if not kong.ctx.plugin.rule_inspection_table_cache[cache_key] then
                            kong.ctx.plugin.rule_inspection_table_cache[cache_key] = {}
                            local value_table = self:__add_value_to_rule_inspection_table(condition.transform, v, multi_match_enabled)
                            for _,vcache in pairs(value_table) do
                                table_insert(kong.ctx.plugin.rule_inspection_table_cache[cache_key], vcache)
                            end
                        else
                            --debug("-----------------> Using cache for "..variable)
                            for _,vv in pairs(kong.ctx.plugin.rule_inspection_table_cache[cache_key]) do
                                table_insert(kong.ctx.plugin.rule_inspection_table, vv)
                            end
                        end
                    end
                end
            end
        end
    end


    -- start rule control actions
    if rule.rule_control then
        for _,rulec in pairs(rule.rule_control) do
            if rulec.remove_variable_rx then
                local key_pattern = string_gsub("^" .. rulec.remove_variable_rx.name, "%.", "%%.")
                local value_rx = rulec.remove_variable_rx.rx

                --debug("removing key START")
                for k,v in pairs(kong.ctx.plugin.rule_inspection_table) do
                    for key, value in pairs(v) do
                        if string_match(key, key_pattern) then
                            --debug("pattern:"..key_pattern.." -> matched key "..key)
                            --debug("`- check matched key: ".. key .." regex:"..value_rx)
                            if ngx_re_match(key, value_rx, "jo") then
                                -- remove this element from table
                                --debug("----> removing key "..key.." with index n "..k)
                                table.remove(kong.ctx.plugin.rule_inspection_table, k)
                            end
                        end
                    end
                end
            end
        end
    end

    -- start transformation functions
end

_M.convert_inspection_table_value = function(self, name_pattern, new_type, new_prefix)
    for k,v in pairs(kong.ctx.plugin.inspection_table) do
        for key, value in pairs(v) do
            if string_match(key, name_pattern) then
                -- remove this element from table
                table.remove(kong.ctx.plugin.inspection_table, k)

                if new_type == "json" then
                    if pcall(cjson.decode,value) then
                        local new_value = body_parser:json(new_prefix, value)
                        for kk,vv in pairs(new_value) do
                            table_insert(kong.ctx.plugin.inspection_table, vv)
                        end
                    end
                end
            end
        end
    end
end
-- / INSPECTION TABLE FUNCTIONS






_M.__qs_parser = function (self, raw_query_string, try_base64decode_if_possible)
    local values = {}

    if raw_query_string then
        debug("KEY=VALUE Start parsing: " .. raw_query_string)
        for keyval in string_gmatch(raw_query_string, "([^&]+)") do
            debug("         ` key-value: " .. keyval)
            local key,value = string_match(keyval, "([^=]+)=?(.*)")
            if key and value then
                debug("         ` key: " .. key)
                debug("         ` value: " .. value)
                table_insert(values, {
                    ["request.query.name:"..key:lower()] = key
                })
                table_insert(values, {
                    ["request.query.value:"..key:lower()] = value
                })

                if try_base64decode_if_possible then
                    value = string_gsub(value, "+", "-")
                    value = string_gsub(value, "/", "_")

                    -- replace %3d with =
                    value = string_gsub(value, "%%3d", "=")

                    -- use pcall to catch errors
                    local status, decoded = pcall(b64.decode_base64url, value)
                    if status then
                        table_insert(values, {
                            ["request.query.value:"..key:lower().."_ka_b64_decoded"] = tostring(decoded)
                        })
                    end
                end
            else
                debug("         ` key2: " .. keyval)
                table_insert(values, {
                    ["request.query.name:"..keyval:lower()] = keyval
                })

                if try_base64decode_if_possible then
                    keyval = string_gsub(keyval, "+", "-")
                    keyval = string_gsub(keyval, "/", "_")

                    -- replace %3d with =
                    keyval = string_gsub(keyval, "%%3d", "=")

                    -- use pcall to catch errors
                    local status, decoded = pcall(b64.decode_base64url, keyval)
                    if status then
                        table_insert(values, {
                            ["request.query.value:"..keyval:lower().."_ka_b64_decoded"] = tostring(decoded)
                        })
                        debug("         ` BASE64 DECODED on key2: " .. keyval)
                        debug("         ` BASE64 DECODED value2: " .. tostring(decoded))
                    end
                end
            end
        end
        -- if len raw_querystring > 0 and character = not in raw_query_string
        if string_len(raw_query_string) > 0 and not string_match(raw_query_string, "=") then
            table_insert(values, {
                ["request.query.name:"..raw_query_string:lower()] = raw_query_string
            })
            table_insert(values, {
                ["request.query.value:"..raw_query_string:lower()] = ""
            })
            
            if try_base64decode_if_possible then
                raw_query_string = string_gsub(raw_query_string, "+", "-")
                raw_query_string = string_gsub(raw_query_string, "/", "_")

                -- replace %3d with =
                raw_query_string = string_gsub(raw_query_string, "%%3d", "=")

                -- use pcall to catch errors
                local status, decoded = pcall(b64.decode_base64url, raw_query_string)
                if status then
                    table_insert(values, {
                        ["request.query.value:"..raw_query_string:lower().."_ka_b64_decoded"] = decoded
                    })
                end
            end
        end
    end -- end if body

    return values
end

_M.__apply_transformation = function(self, tfunc, value)
    local cache_key = md5(tfunc..value)
    --kong.log.debug("Setting Cache key: "..cache_key)

    if kong.ctx.plugin.ka_value_cache[cache_key] then
        kong.log.debug("Using cache for transformation: "..tfunc.." on value: "..tostring(value).. " -> "..tostring(kong.ctx.plugin.ka_value_cache[cache_key]))
        return kong.ctx.plugin.ka_value_cache[cache_key]
    end

    -- kong.log.debug("Applying transformation: "..tfunc.." on value: "..tostring(value))

    local result_string = value

    if tfunc == "hexSequenceDecode" then
        -- decode %HH sequences
        result_string = string_gsub(result_string, "%%(%x%x)", function(hex)
            return string_char(tonumber(hex, 16))
        end)
        --kong.log.debug("Hex Sequence Decode applied on value: "..tostring(value).." -> "..tostring(result_string))
    end

    if tfunc == "urlDecodeUni" or tfunc == "urlDecode" then
        local string_can_be_decoded = true
        -- check first if value contains characters: %, +, 0x
        if not string_match(value, "%%") and not string_match(value, "%+") and not string_match(value, "＜") and not string_match(value, "＞") then
            string_can_be_decoded = false
        end

        if string_can_be_decoded then
            -- convert all + to space
            result_string = string_gsub(result_string, "+", " ")

            -- for loop 3 times
            -- if %uHHHH is in the string
            -- **************************** uhmm this is not clear... need a refactor
            for i=1,3 do
                if string_match(result_string, "%%u%x%x%x%x") then
                    result_string = string_gsub(result_string, "%%u(%x%x%x%x)", function(hex)
                        return utils:utf8FromHex(hex)
                    end)
                end
            end

            -- for loop 3 times
            for i=1,3 do
                if string_match(result_string, "%%%x%x") then
                    result_string = ngx.unescape_uri(result_string)
                end
            end

            -- 0xHH decoding disabled: not part of ModSecurity urlDecodeUni standard
            -- see: ModSecurity url_decode_uni.cc — only decodes %HH, %uHHHH, and + as space
            --[[
            for i=1,3 do
                if string_match(result_string, "0x%x%x") then
                    result_string = string_gsub(result_string, "0x(%x%x)", function(hex)
                        return string_char(tonumber(hex, 16))
                    end)
                end
            end
            ]]--

            -- replace ＜ with < in result_string
            result_string = string_gsub(result_string, "＜", "<")
            -- replace ＞ with > in result_string
            result_string = string_gsub(result_string, "＞", ">")

            -- remove all null byte from result_string
            --result_string = string_gsub(result_string, "%z", "")
        end

        --kong.log.debug("URL Decode applied on value: "..tostring(value).." -> "..tostring(result_string))
    end

    if tfunc == "replaceComments" then
        -- remove all comments
        result_string = string_gsub(result_string, "/%*.-%*/", "")
        result_string = string_gsub(result_string, "//.-\n", "")
    end

    -- removeCommentsChar
    -- Removes common comments chars (/*, */, --, #).
    if tfunc == "removeCommentsChar" then
        -- remove all comments
        result_string = string_gsub(result_string, "/%*", "")
        result_string = string_gsub(result_string, "%*/", "")
        result_string = string_gsub(result_string, "//", "")
        result_string = string_gsub(result_string, "#", "")
    end

    if tfunc == "removeWhitespace" then
        -- remove all whitespaces
        result_string = string_gsub(result_string, "%s+", "")
    end

    -- Removes multiple slashes, directory self-references, and directory back-references (except when at the beginning of the input) from input string.
    if tfunc == "normalisePath" then

        -- remove directory self-references
        result_string = string_gsub(result_string, "/%./", "/")
        
        -- remove directory back-references
        result_string = string_gsub(result_string, "/%.%./", "/")
        
        -- remove multiple slashes
        result_string = string_gsub(result_string, "/+", "/")
    end

    if tfunc == "lowercase" then
        result_string = string_lower(result_string)
    end

    if tfunc == "cmdLine" then
        --[[
            deleting all backslashes [\]
            deleting all double quotes ["]
            deleting all single quotes [']
            deleting all carets [^]
            deleting spaces before a slash /
            deleting spaces before an open parentesis [(]
            replacing all commas [,] and semicolon [;] into a space
            replacing all multiple spaces (including tab, newline, etc.) into one space
            transform all characters to lowercase
        ]]--
        result_string = string_gsub(result_string, "[\\\"'^]", "")
        result_string = string_gsub(result_string, "%s+/", "/")
        result_string = string_gsub(result_string, "%s+[(]", "(")
        result_string = string_gsub(result_string, "[,;]", " ")
        result_string = string_gsub(result_string, "%s+", " ")
        result_string = string_lower(result_string)

    end

    if tfunc == "escapeSeqDecode" then
        -- Decodes ANSI C escape sequences: \a, \b, \f, \n, \r, \t, \v, \\, \?, \', \", \xHH (hexadecimal), \0OOO (octal). Invalid encodings are left in the output.
        result_string = string_gsub(result_string, "\\a", "\a")
        result_string = string_gsub(result_string, "\\b", "\b")
        result_string = string_gsub(result_string, "\\f", "\f")
        result_string = string_gsub(result_string, "\\n", "\n")
        result_string = string_gsub(result_string, "\\r", "\r")
        result_string = string_gsub(result_string, "\\t", "\t")
        result_string = string_gsub(result_string, "\\v", "\v")
        result_string = string_gsub(result_string, "\\\\", "\\")
        --result_string = string_gsub(result_string, "\\?", "?")
        result_string = string_gsub(result_string, "\\'", "'")
        result_string = string_gsub(result_string, '\\"', '"')
        result_string = string_gsub(result_string, "\\x(%x%x)", function(hex)
            return string_char(tonumber(hex, 16))
        end)
        result_string = string_gsub(result_string, "\\0(%d%d%d)", function(octal)
            return string_char(tonumber(octal, 8))
        end)
    end

    -- htmlEntityDecode
    --[[
        Decodes the characters encoded as HTML entities. The following variants are supported:
        HH and HH; (where H is any hexadecimal number)
        DDD and DDD; (where D is any decimal number)
        &quotand"
        &nbspand 
        &ltand<
        &gtand>
    ]]--
    if tfunc == "htmlEntityDecode" then
        result_string = string_gsub(result_string, "&#x(%x%x);", function(hex)
            return string_char(tonumber(hex, 16))
        end)

        --[[
        -- convert &#%d%d; to char
        new_value = string_gsub(new_value, "&#(%d%d);", function(dec)
            return string_char(tonumber(dec, 10))
        end)

        -- convert &#%d%d%d; to char
        new_value = string_gsub(new_value, "&#(%d%d%d);", function(dec)
            return string_char(tonumber(dec, 10))
        end)

        -- convert &#%d%d%d%d; to char
        new_value = string_gsub(new_value, "&#(%d%d%d%d);", function(dec)
            return string_char(tonumber(dec, 10))
        end)
        ]]--

        -- convert &#%d+; to char
        result_string = string_gsub(result_string, "&#(%d+);", function(dec)
            return string_char(tonumber(dec, 10))
        end)

        result_string = string_gsub(result_string, "&quot;", '"')
        result_string = string_gsub(result_string, "&nbsp;", " ")
        result_string = string_gsub(result_string, "&lt;", "<")
        result_string = string_gsub(result_string, "&gt;", ">")
        --kong.log.debug("HTML Entity Decode applied on value: "..tostring(value).." -> "..tostring(result_string))
    end

    -- utf8toUnicode
    --[[ 
        Converts all UTF-8 character sequences to Unicode (using '%uHHHH' format). 
        This help input normalization specially for non-english languages minimizing
        false-positives and false-negatives.
    ]]--
    if tfunc == "utf8toUnicode" then
        --[[local new_value = string_gsub(value, "([\194-\244][\128-\191])", function(c)
            local byte = {string.byte(c, 1, -1)}
            return string.format("%%u%04x", byte[1]*64+byte[2]-12416)
        end)]]
        -- use utils:hexFromUTF8() to convert UTF-8 char to escape sequence
        --[[local new_value = ngx.re.gsub(value, "([\x00-\x7F]|[\xC2-\xF4][\x80-\xBF]{1,3})", function(c)
            debug("TFUNC utf8toUnicode -> Converting: "..c.." to:" .. utils:hexFromUTF8(c))
            return utils:hexFromUTF8(c)
        end)]]--

        local chars_to_replace = ngx.re.gsub(result_string, "([\x00-\x7F]|[\xC2-\xF4][\x80-\xBF]{1,3})")

        if chars_to_replace then
            if type(chars_to_replace) == "string" then
                chars_to_replace = {chars_to_replace}
            end
            for _,c in pairs(chars_to_replace) do
                --debug("TFUNC utf8toUnicode -> Converting: "..c.." to:" .. utils:hexFromUTF8(c))
                result_string = string_gsub(result_string, c, utils:hexFromUTF8(c))
            end
        end
    end

    --[[
        jsDecode
        Decodes JavaScript escape sequences. If a \uHHHH code is in the range of FF01-FF5E 
        (the full width ASCII codes), then the higher byte is used to detect and adjust the 
        lower byte. Otherwise, only the lower byte will be used and the higher byte zeroed 
        (leading to possible loss of information).
    ]]--
    if tfunc == "jsDecode" then
        result_string = string_gsub(result_string, "\\u(%x%x%x%x)", function(unicode)
            local code = tonumber(unicode, 16)
            if code >= 0xFF01 and code <= 0xFF5E then
                return string_char(code - 0xFEE0)
            else
                return string_char(code)
            end
        end)
    end

    --[[
        cssDecode
        Decodes characters encoded using the CSS 2.x escape rules syndata.html#characters. 
        This function uses only up to two bytes in the decoding process, meaning that it is 
        useful to uncover ASCII characters encoded using CSS encoding (that wouldn’t normally 
        be encoded), or to counter evasion, which is a combination of a backslash and 
        non-hexadecimal characters (e.g., ja\vascript is equivalent to javascript).
    ]]--
    if tfunc == "cssDecode" then
        result_string = string_gsub(value, "\\([0-9a-fA-F]{1,2})", function(hex)
            return string_char(tonumber(hex, 16))
        end)
    end

    --[[
        removeNulls
        Removes all NUL bytes from input.
    ]]--
    if tfunc == "removeNulls" then
        result_string = string_gsub(value, "%z", "")
    end

    --[[
        length
        return the string length of the variable
    ]]--
    if tfunc == "length" then
        result_string = string_len(result_string)
    end

    --[[
        base64Decode
    ]]
    if tfunc == "base64Decode" then
        local b64encoded = ngx_decode_base64(result_string)
        if b64encoded then
            result_string = b64encoded
        end
    end

    --[[
        validateUtf8Encoding
        Check whether the input is a valid UTF-8 string.

        The @validateUtf8Encoding operator detects the following problems:

        - Not enough bytes : UTF-8 supports two-, three-, four-, five-, and six-byte encodings. ModSecurity will locate cases when one or more bytes is/are missing from a character.
        - Invalid characters : The two most significant bits in most characters should be fixed to 0x80. Some attack techniques use different values as an evasion technique.
        - Overlong characters : ASCII characters are mapped directly into UTF-8, which means that an ASCII character is one UTF-8 character at the same time. However, in UTF-8 many ASCII characters can also be encoded with two, three, four, five, and six bytes. This is no longer legal in the newer versions of Unicode, but many older implementations still support it. The use of overlong UTF-8 characters is common for evasion.

        Notes:
        Most, but not all applications use UTF-8. If you are dealing with an application that does, validating that all request parameters are valid UTF-8 strings is a great way to prevent a number of evasion techniques that use the assorted UTF-8 weaknesses. False positives are likely if you use this operator in an application that does not use UTF-8.
        Many web servers will also allow UTF-8 in request URIs. If yours does, you can verify the request URI using @validateUtf8Encoding.
    ]]--
    if tfunc == "validateUtf8Encoding" then
        if not pcall(function() result_string = string_match(result_string, "^[\128-\191]*$") end) then
            result_string = value
        end
    end


    -- save to cache
    kong.ctx.plugin.ka_value_cache[cache_key] = result_string

    return result_string
end

_M.__fix_matching_parts = function(self, rule, matched_parts)
    for _,mp in pairs(matched_parts) do
        --inspect(mp)

        -- on path
        local m = string_match(mp.matched_on, '^request%.raw%_path$')
        if m then
            debug("Fixing matched part: request.raw_path")
            local raw_path = kong.request.get_raw_path()
            raw_path = string_gsub(raw_path, "%%", "")
            raw_path = string_gsub(raw_path, "\\", "")
            raw_path = string_gsub(raw_path, rule.action.fix_matched_parts.remove_chars_pattern, "")
            kong.service.request.set_path(raw_path)
        end

        -- on querystring
        local m = string_match(mp.matched_on, '^request%.query%.value%:(.+)$')
        if m then
            local qs = kong.request.get_query()
            for k,v in pairs(qs) do
                if k == m then
                    debug("Fixing matched part: request.query.value:"..m)
                    qs[k] = string_gsub(qs[k], "%%", "")
                    qs[k] = string_gsub(qs[k], "\\", "")
                    qs[k] = string_gsub(qs[k], rule.action.fix_matched_parts.remove_chars_pattern, "")
                end
            end
            kong.service.request.set_query(qs)
        end

        -- on request header values
        local m = string_match(mp.matched_on, '^request%.header%.value%:(.+)$')
        if m then
            local matched_header_value = request_get_header(m)
            if matched_header_value then
                debug("Fixing matched part: request.header.value:"..m)
                matched_header_value = string_gsub(matched_header_value, "%%", "")
                matched_header_value = string_gsub(matched_header_value, "\\", "")
                matched_header_value = string_gsub(matched_header_value, rule.action.fix_matched_parts.remove_chars_pattern, "")

                kong.service.request.set_header(m, matched_header_value)
            end
        end

        -- on body args
        local m = string_match(mp.matched_on, '^request%.body')
        if m then
            local body = request_get_raw_body()
            -- if not body, but content-length is set, then try to use ngx.req.get_body_file
            -- ngx.req.get_body_file: Retrieves the file name for the in-file request body data. Returns nil if the request body has not been read or has been read into memory.
            if not body then
                local content_length = request_get_headers()["content-length"]
                if content_length then
                    local body_file = ngx_req_get_body_file()
                    if body_file then
                        local file = io.open(body_file, "r")
                        if file then
                            body = file:read("*a")
                            file:close()
                        end
                    end
                end
            end
            if body then
                debug("Fixing matched part: request.body")
                body = string_gsub(body, "%%", "")
                body = string_gsub(body, "\\", "")
                body = string_gsub(body, rule.action.fix_matched_parts.remove_chars_pattern, "")
                kong.service.request.set_raw_body(body)
            end
        end
    end
end

--[[_M.__set_local_variables = function(self, plugin_conf)
    kong.ctx.plugin.rule_variables = {}

    local request_method = request_get_method()
    local request_method_is_allowed = false
    for k,v in pairs(plugin_conf.request_methods_allowed) do
        if request_method == v then
            request_method_is_allowed = true
            break
        end
    end
    if not request_method_is_allowed then
        kong.ctx.plugin.rule_variables["request_method_denied"] = request_method
    end

    local request_headers = request_get_headers()
    for k,v in pairs(plugin_conf.request_headers_denied) do
        if request_headers[v] then
            kong.ctx.plugin.rule_variables["request_headers_denied"] = v
            break
        end
    end
end]]--

_M.__set_log_field = function(self, field_name, field_value)
    if not kong.ctx.plugin.additional_log_fields then
        kong.ctx.plugin.additional_log_fields = {}
    end
    kong.ctx.plugin.additional_log_fields[field_name] = field_value
end

_M.resolve_variable = function(self, variable)
    local value = variable

    -- if variable matches %{\S+}
    local m = ngx_re_match(variable, "^%\\{([^}]+)\\}", "jo")
    if m then
        local var_name_raw = m[1]
        -- escape all characters to be escaped for string match
        local var_name = var_name_raw:gsub("([%-%.%+%[%]%(%)%$%^%%%?%*])", "%%%1")
        local value_list = self:__get_value_from_inspection_table(var_name)
        if value_list then
            for k,v in pairs(value_list[1]) do
                value = v
            end
        end
    end

    return value
end

_M.replace_variable_in_string = function(self, str)
    -- get service id
    local service = kong.router.get_service()

    local new_str = str
    for variable in string_gmatch(str, "%%{([^}]+)}") do
        debug("replace_variable_in_string ---> replacing variable: "..variable)
        local var_name = variable:gsub("([%-%.%+%[%]%(%)%$%^%%%?%*])", "%%%1")
        local value_list = self:__get_value_from_inspection_table(var_name)
        if value_list then
            for k,v in pairs(value_list[1]) do
                debug("replace_variable_in_string ---> replacing variable: "..variable.." with value: "..v)
                new_str = string_gsub(new_str, "%%{"..variable.."}", v)
            end
        end
    end

    return new_str
end

_M.check_arg_len = function(self, plugin_conf)
    local arg_num_count = 0
    local res = {
        matched = false,
        message = "",
        matched_key = "",
        matched_value = "",
        configured_limit = 0
    }

    for _,v in pairs(kong.ctx.plugin.inspection_table) do
        for key, value in pairs(v) do
            if string_match(key, "^request%..*%.name%:.*") then
                arg_num_count = arg_num_count + 1
                if #key > plugin_conf.limit_arg_name_length then
                    res = {
                        matched = true,
                        message = "Argument name length limit reached",
                        matched_key = key,
                        matched_value = value,
                        configured_limit = plugin_conf.limit_arg_name_length
                    }
                    --return true, "Argument name length limit reached", key, value, plugin_conf.limit_arg_name_length
                end
            end
            if string_match(key, "^request%..*%.value%:.*") then
                if #value > plugin_conf.limit_arg_value_length then
                    res = {
                        matched = true,
                        message = "Argument value length limit reached",
                        matched_key = key,
                        matched_value = value,
                        configured_limit = plugin_conf.limit_arg_value_length
                    }
                    --return true, "Argument value length limit reached", key, value, plugin_conf.limit_arg_value_length
                end
            end
        end
    end

    if arg_num_count > plugin_conf.limit_arg_num then
        res = {
            matched = true,
            message = "Argument number limit reached",
            matched_key = "",
            matched_value = "",
            configured_limit = plugin_conf.limit_arg_num
        }
        --return true, "Argument number limit reached", "limit_arg_num", arg_num_count, plugin_conf.limit_arg_num
    end

    if res.matched then
        local response_status_override = 200
        if plugin_conf.engine_blocking_mode then
            response_status_override = 400
        end

        table_insert(kong.ctx.plugin.ka_matched_rules, {
            rule = {
                id = "check_arg_len",
                log = true,
                logdata = "Matched key: "..res.matched_key.." - configured limit: "..res.configured_limit,
                message = res.message,
                phase = "access",
                tags = { "karna", "access", "paranoia-level/1" },
                response_status_override = response_status_override
            },
            part = {
                {
                    matched_on = res.matched_key,
                    matched_value = tostring(#res.matched_value)
                }
            }
        })

        -- if blocking mode, then return 400
        if plugin_conf.engine_blocking_mode then
            return kong.response.exit(
                400,
                "Request argument length limit reached",
                {
                    ["content-type"] = "text/plain",
                    ["cache-control"] = "max-age=0, private, no-store, no-cache, must-revalidate"
                }
            )
        end
    end
end

_M.uri_path_check_violation = function(self, plugin_conf)
    local raw_path = request_get_raw_path()
    local matched = false

    -- check for illegal characters in URI path
    if plugin_conf.check_invalid_chars_in_path then
        local i,c = raw_path:gsub("%%[8-9A-B][0-9a-fA-F]", "")
        debug("--------> SCORE URI PATH CHECK invalid chars: "..tostring(c))

        local limit = plugin_conf.limit_invalid_chars_in_path or 1
        if c >= limit then
            matched = true
        else
            debug("--------> SCORE URI PATH CHECK invalid chars: found:"..tostring(c).." expected:"..tostring(limit))
        end
    end

    -- urldecode raw_path
    raw_path = ngx.unescape_uri(raw_path)

    if plugin_conf.try_bas64decode_if_possible then
        -- remove the first characters if they are /
        raw_path = string_gsub(raw_path, "^[/]*", "")

        -- replace %3d with =
        raw_path = string_gsub(raw_path, "%%3[dD]", "=")

        -- extract base64 string from raw_path using global match
        -- and then replace the decoded value to raw_path
        local base64_strings = {}
        for base64_string in string_gmatch(raw_path, "([A-Za-z0-9%+/=]+)") do
            table_insert(base64_strings, base64_string)
        end

        for _,base64_string in pairs(base64_strings) do
            base64_string = string_gsub(base64_string, "+", "-")
            base64_string = string_gsub(base64_string, "/", "_")
            -- USE pcall to catch errors
            local status, decoded = pcall(b64.decode_base64url, base64_string)
            if status then
                -- escape special characters to avoid invalid capture index error
                decoded = string_gsub(tostring(decoded), "([%-%.%+%[%]%(%)%$%^%%%?%*])", "%%%1")
                raw_path = string_gsub(raw_path, base64_string, decoded)
            end
        end
    end

    -- check if request_get_raw_path() contains characters:
    if plugin_conf.check_special_chars_in_path then
        local limit = plugin_conf.limit_special_chars_in_path or 3

        -- (, ), <, >, =, ;, &, {, }
        -- then count the characters found, and if > then 3 block request
        local chars = {"%(", "%)", "%<", "%>", "%=", "%;", "%&", "%{", "%}", "%*", "%'", '%"', "%%25", "%:"}
        --inspect(chars)
        --local i,c = raw_path:gsub("["..table.concat(chars).."]", " ")
        local c = 0
        for _,v in pairs(chars) do
            if string_match(raw_path, v) then
                c = c + 1
            end
        end
        debug("--------> SCORE URI PATH CHECK special chars: "..tostring(c))
        if c >= limit then
            matched = true
        end
    end

    if matched then
        -- table insert a new entry on kong.ctx.plugin.ka_matched_rules
        local response_status_override = 200
        if plugin_conf.engine_blocking_mode then
            response_status_override = 403
        end

        table_insert(kong.ctx.plugin.ka_matched_rules, {
            rule = {
                id = "uri_path_check_violation",
                log = true,
                logdata = "",
                message = "Request URI path contains illegal characters",
                phase = "access",
                tags = { "karna", "access", "paranoia-level/1" },
                response_status_override = response_status_override
            },
            part = {
                {
                    matched_on = "request.raw_path",
                    matched_value = raw_path
                }
            }
        })

        -- if blocking mode, then return 403
        if plugin_conf.engine_blocking_mode then
            return kong.response.exit(
                403,
                "Request URI path contains illegal characters",
                {
                    ["content-type"] = "text/plain",
                    ["cache-control"] = "max-age=0, private, no-store, no-cache, must-revalidate"
                }
            )
        end
    end
end

_M.check_request_headers_allowed = function(self, plugin_conf)
    local matched = false
    local duplicated = false
    local request_headers_lowercase_name = {}

    local request_headers = request_get_headers()
    for k,v in pairs(request_headers) do
        if type(v) == "string" then
            request_headers_lowercase_name[k:lower()] = v
        else
            duplicated = k:lower()
        end
    end

    for _,header in pairs(plugin_conf.request_headers_denied) do
        if request_headers_lowercase_name[header] then
            matched = header
            break
        end
    end

    if matched then
        -- table insert a new entry on kong.ctx.plugin.ka_matched_rules
        local response_status_override = 200
        if plugin_conf.engine_blocking_mode then
            response_status_override = 403
        end

        table_insert(kong.ctx.plugin.ka_matched_rules, {
            rule = {
                id = "check_request_headers_allowed",
                log = true,
                logdata = "Request header name: " .. matched,
                message = "Request header not allowed",
                phase = "access",
                tags = { "karna", "access", "paranoia-level/1" },
                response_status_override = response_status_override
            },
            part = {
                {
                    matched_on = "request.header.name:"..matched,
                    matched_value = matched
                }
            }
        })

        -- if blocking mode, then return 403
        if plugin_conf.engine_blocking_mode then
            return kong.response.exit(
                403,
                "Request headers not allowed",
                {
                    ["content-type"] = "text/plain",
                    ["cache-control"] = "max-age=0, private, no-store, no-cache, must-revalidate"
                }
            )
        end
    end

    if duplicated then
        -- table insert a new entry on kong.ctx.plugin.ka_matched_rules
        local response_status_override = 200
        if plugin_conf.engine_blocking_mode then
            response_status_override = 403
        end

        table_insert(kong.ctx.plugin.ka_matched_rules, {
            rule = {
                id = "check_request_headers_allowed",
                log = true,
                logdata = "Request header name: " .. duplicated,
                message = "Request header name duplicated",
                phase = "access",
                tags = { "karna", "access", "paranoia-level/1" },
                response_status_override = response_status_override
            },
            part = {
                {
                    matched_on = "request.header.name:"..duplicated,
                    matched_value = duplicated
                }
            }
        })

        -- if blocking mode, then return 403
        if plugin_conf.engine_blocking_mode then
            return kong.response.exit(
                403,
                "Request headers not allowed",
                {
                    ["content-type"] = "text/plain",
                    ["cache-control"] = "max-age=0, private, no-store, no-cache, must-revalidate"
                }
            )
        end
    end
end

_M.check_request_content_type_charset = function(self, plugin_conf)
    local matched = false

    local request_content_type = request_get_header("content-type")
    if request_content_type then
        local content_type, charset = string_match(request_content_type, "(.-);%s*charset=(.+)")
        if content_type and charset then
            for _,c in pairs(plugin_conf.request_content_type_allowed) do
                if content_type:lower() == c then
                    matched = true
                end
            end

            if not matched then
                -- table insert a new entry on kong.ctx.plugin.ka_matched_rules
                local response_status_override = 200
                if plugin_conf.engine_blocking_mode then
                    response_status_override = 403
                end
        
                table_insert(kong.ctx.plugin.ka_matched_rules, {
                    rule = {
                        id = "check_request_content_type_charset",
                        log = true,
                        logdata = "",
                        message = "Request Content-Type charset not allowed",
                        phase = "access",
                        tags = { "karna", "access", "paranoia-level/1" },
                        response_status_override = response_status_override
                    },
                    part = {
                        {
                            matched_on = "request.header.value:content-type",
                            matched_value = request_content_type
                        }
                    }
                })
        
                -- if blocking mode, then return 403
                if plugin_conf.engine_blocking_mode then
                    return kong.response.exit(
                        403,
                        "Request Content-Type charset not allowed",
                        {
                            ["content-type"] = "text/plain",
                            ["cache-control"] = "max-age=0, private, no-store, no-cache, must-revalidate"
                        }
                    )
                end
            end
        end
    end
end

return _M

