local plugin = {
  PRIORITY = 8300,
  VERSION = "1.0.0",
}

local ngx                 = ngx
local kong                = kong
local response_exit       = kong.response.exit
local response_set_header = kong.response.set_header

local engine            = require "kong.plugins.karna.ka_engine"
local body_parser       = require "kong.plugins.karna.ka_body_parser"
local utils             = require "kong.plugins.karna.ka_utils"
local seclang           = require "kong.plugins.karna.ka_seclang"
local ka_mcp            = require "kong.plugins.karna.ka_mcp"
local lrucache          = require "resty.lrucache"
local cjson             = require "cjson"
local ipmatcher         = require "resty.ipmatcher"

local ka_rules, err = lrucache.new(10000)

--local debug = function(i) return end
--local inspect = function(i) return end
local debug = kong.log.debug
local inspect = kong.log.inspect

local evaluate_rules = function(plugin_conf, rules, phase)
  local is_rule_matched, rule_matched_obj, matches_info, err = engine:loop_rules(plugin_conf, rules, phase)
  if err then
    debug("Error looping local rules: "..err)
    response_exit(
      500,
      "Error looping local rules: "..err,
      {
        ["content-type"] = "text/plain",
        ["cache-control"] = "max-age=0, private, no-store, no-cache, must-revalidate"
      }
    )
  end
  if is_rule_matched then

    -- mcp_event-phase rules don't terminate the request (headers already
    -- sent). Stash the action on kong.ctx.plugin.mcp.event_action; the
    -- caller (ka_mcp.body_filter) reads it and rewrites the SSE chunk.
    if phase == "mcp_event"
       and rule_matched_obj.action
       and rule_matched_obj.action.mcp_event_action
       and kong.ctx.plugin.mcp then
      kong.ctx.plugin.mcp.event_action = rule_matched_obj.action.mcp_event_action
      return
    end

    -- if blocking mode enabled, exit with error
    if plugin_conf.engine_blocking_mode then
      if rule_matched_obj.action then

        if rule_matched_obj.action.fixed_response then
          if plugin_conf.private_debug then
            response_exit(
              rule_matched_obj.action.fixed_response.status_code or 403,
              cjson.encode(rule_matched_obj),
              rule_matched_obj.action.fixed_response.headers or { ["content-type"] = "text/plain", ["cache-control"] = "max-age=0, private, no-store, no-cache, must-revalidate" }
            )
          else
            response_exit(
              rule_matched_obj.action.fixed_response.status_code or 403,
              rule_matched_obj.action.fixed_response.body or "Access Denied",
              rule_matched_obj.action.fixed_response.headers or { ["content-type"] = "text/plain", ["cache-control"] = "max-age=0, private, no-store, no-cache, must-revalidate" }
            )
          end
        end

      end
    end

    if rule_matched_obj.rule_control then
      for _,control in pairs(rule_matched_obj.rule_control) do

        if control.remove_rule then
          if control.remove_rule.rule_id then
            kong.ctx.plugin.rule_controls.ids[control.remove_rule.rule_id] = { action = "remove" }
          end
        end

        if control.remove_target_rule_by_tag then
          if control.remove_target_rule_by_tag.tag then

            -- this means remove all rules
            if control.remove_target_rule_by_tag.tag == "OWASP_CRS" then
              table.insert(kong.ctx.plugin.rule_controls.remove_target_from_all_rules, control.remove_target_rule_by_tag.name)
            else
              -- normal behavior
              if not kong.ctx.plugin.rule_controls.tags[control.remove_target_rule_by_tag.tag] then
                kong.ctx.plugin.rule_controls.tags[control.remove_target_rule_by_tag.tag] = {
                  action = "remove_target",
                  target = { control.remove_target_rule_by_tag.name }
                }
              else
                table.insert(kong.ctx.plugin.rule_controls.tags[control.remove_target_rule_by_tag.tag].target, control.remove_target_rule_by_tag.name)
              end
            end

          end
        end

      end
    end

  end
end

function plugin:init_worker()
  if ka_rules then
    debug("Loading rules on worker number "..ngx.worker.id())

    local rules = {}
    local rcontrol_rules = {}
    local dfiles = {}

    -- flush ka_rules cache
    ka_rules:flush_all()

    -- set rule to cache
    rules, rcontrol_rules, dfiles = engine:load_rules()
    ka_rules:set("ka_rules", rules)
    ka_rules:set("rcontrol_rules", rcontrol_rules)

    -- set dfiles to cache
    local ka_dfiles = {}
    for condition_value,dfile in pairs(dfiles) do
      ka_dfiles[condition_value] = dfile
    end
    ka_rules:set("ka_dfiles", ka_dfiles)

    debug("#########> Loaded "..tostring(#rules).." global rules on worker number "..ngx.worker.id())
  end
end

function plugin:access(plugin_conf)
  -- skip access phase if response sent from cache
  if kong.ctx.shared.response_from_cache then
    return
  end

  -- if ignore from local IPs
  if plugin_conf.ignore_from_local_ips then
    local local_ips = ipmatcher.new({
        "127.0.0.0/8",
        "192.168.0.0/16",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "::1",
        "fe80::/32"
    })

    if local_ips:match(ngx.var.remote_addr) then
        debug("Ignoring request from local IP: " .. ngx.var.remote_addr)
        return
    end
  end

  -- value cache
  kong.ctx.plugin.ka_value_cache = {}
  kong.ctx.plugin.ka_variable_cache = {}

  -- MCP detection + JSON-RPC envelope parsing. No-op when mcp_enabled=false.
  -- Populates kong.ctx.plugin.mcp consumed later by the variable resolver
  -- and by the mcp_method_in / mcp_jsonrpc_valid operators.
  if plugin_conf.mcp_enabled then
    ka_mcp.detect(plugin_conf)
    ka_mcp.parse_request(plugin_conf)
  end

  -- Rule Evaluation (access phase)
  kong.ctx.plugin.ka_matched_rules = {}

  -- Variables that can be overwritten by rules
  kong.ctx.plugin.enable_check_arg_len = true

  -- check if method is allowed
  engine:method_allowed(plugin_conf)

  -- check path violations
  engine:uri_path_check_violation(plugin_conf)

  -- check request headers allowed
  engine:check_request_headers_allowed(plugin_conf)

  -- check if content-type charset is allowed
  engine:check_request_content_type_charset(plugin_conf)

  -- set local variables
  kong.ctx.plugin.rule_variables = {}

  -- set transaction variables (for setvar support)
  kong.ctx.plugin.tx_variables = {}

  -- set rule controls
  kong.ctx.plugin.rule_controls = {
    ids = {},
    tags = {},
    remove_target_from_all_rules = {}
  }

  -- generate global inspection table
  --engine:get_inspection_table(plugin_conf)

  -- debug inspection table
  --inspect(kong.ctx.plugin.inspection_table)

  -- if dev env enabled and request header x-karna-test-rule-id is set
  --local is_dev_env_enabled = utils:dev_env_enabled()
  --local filter_rule_id = utils:dev_filter_rule_id(is_dev_env_enabled)

  -- get global rules
  local rules = ka_rules:get("ka_rules")
  if rules then
    debug("Loaded "..tostring(#rules).." global rules")
  end

  local rcontrol_rules = ka_rules:get("rcontrol_rules")
  if rcontrol_rules then
    debug("Loaded "..tostring(#rcontrol_rules).." global Rule Control rules")
  end

  -- get dfiles
  local dfiles = ka_rules:get("ka_dfiles")

  -- get service local request rules
  local local_rules_request = {}
  -- Initialize the cross-phase cache so header_filter / body_filter (and
  -- MCP's mcp_event phase) can reach for the parsed local rules without
  -- re-parsing the plugin_conf JSON strings.
  kong.ctx.plugin.local_rules = {}

  if plugin_conf.rules_request and #plugin_conf.rules_request > 0 then
    for _,req_rule_raw in pairs(plugin_conf.rules_request) do
      local rule_is_valid, rule_parser_error = pcall(cjson.decode, req_rule_raw)
      if rule_is_valid then
        local req_rule = cjson.decode(req_rule_raw)
        table.insert(kong.ctx.plugin.local_rules, req_rule)
        if req_rule.phase == "access" then
          kong.log.debug("Adding local request rule ID: "..req_rule.id.." to access phase")
          table.insert(local_rules_request, req_rule)
        end
      else
        kong.log.err("Error parsing JSON rule: "..rule_parser_error)
      end
    end
  end

  -- loop rule control
  evaluate_rules(plugin_conf, rcontrol_rules, "access")

  kong.log.inspect(kong.ctx.plugin.rule_controls)

  -- loop local rules
  if plugin_conf.local_rules_enabled then
    evaluate_rules(plugin_conf, local_rules_request, "access")
  end




  -- loop the OWASP ModSecurity Core Rule Set rules
  if plugin_conf.coreruleset_enabled then
    evaluate_rules(plugin_conf, rules, "access")
  end

  -- default values
  --[[local dev_output = ""

  if is_dev_env_enabled then
    dev_output = cjson.encode(kong.ctx.plugin.inspection_table)
    dev_output = dev_output .. "\n\n" .. cjson.encode(kong.ctx.plugin.rule_inspection_table)
    response_exit(
      200,
      dev_output,
      {
        ["content-type"] = "text/plain",
        ["cache-control"] = "max-age=0, private, no-store, no-cache, must-revalidate"
      }
    )
  end]]--
end

function plugin:header_filter(plugin_conf)
  if kong.ctx.shared.response_from_cache then
    return
  end

  -- set Karna response headers
  if plugin_conf.set_karna_headers then
    response_set_header("X-Karna-Engine", "Karna")
    response_set_header("X-Karna-Engine-Version", plugin.VERSION)
  end

  -- MCP: detect SSE response (Content-Type: text/event-stream) and arm
  -- the reassembler for body_filter. No-op for non-MCP traffic.
  if plugin_conf.mcp_enabled then
    ka_mcp.header_filter(plugin_conf)
  end

  -- generate global inspection table
  engine:get_inspection_table(plugin_conf)

  -- get global rules
  local rules = ka_rules:get("ka_rules")
  if rules then
    debug("Loaded "..tostring(#rules).." global rules")
  end

  -- get service local request rules
  local local_rules_request = {}
  if kong.ctx.plugin.local_rules then
    for _,req_rule in pairs(kong.ctx.plugin.local_rules) do
      if req_rule.phase == "header_filter" then
        table.insert(local_rules_request, req_rule)
      end
    end
  end

  -- local rules
  if plugin_conf.local_rules_enabled then
    --engine:loop_rules(plugin_conf, local_rules_request, "header_filter", local_rules_request, false, nil, nil, nil)
  end
end

function plugin:body_filter(plugin_conf)
  if kong.ctx.shared.response_from_cache then
    return
  end

  -- MCP streaming: reassembles SSE events from upstream chunks and
  -- evaluates `mcp_event`-phase rules per event. Mutates ngx.arg[1] in
  -- place to drop/replace/inject/terminate events. No-op for non-MCP
  -- traffic or non-streaming responses.
  if plugin_conf.mcp_enabled then
    ka_mcp.body_filter(plugin_conf, evaluate_rules)
  end

  -- get service local request rules
  local local_rules_request = {}
  if kong.ctx.plugin.local_rules then
    for _,req_rule in pairs(kong.ctx.plugin.local_rules) do
      if req_rule.phase == "header_filter" then
        table.insert(local_rules_request, req_rule)
      end
    end
  end

  -- local rules
  if plugin_conf.local_rules_enabled then
    --engine:loop_rules(plugin_conf, local_rules_request, "body_filter", local_rules_request, false, nil, nil, nil)
  end
end

function plugin:log(plugin_conf)
  -- this phase doesn't need to be skipped
  -- if response is sent from cache due to
  -- logging purposes

  if plugin_conf.auditlog_enabled then
    if plugin_conf.ignore_from_local_ips then
      local local_ips = ipmatcher.new({
        "127.0.0.0/8",
        "192.168.0.0/16",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "::1",
        "fe80::/32"
      })

      if local_ips:match(ngx.var.remote_addr) then
        debug("Ignoring request from local IP: " .. ngx.var.remote_addr)
        return
      end
    end

    -- collect matched rules with log=true
    local loggable_matches = {}
    if kong.ctx.plugin.ka_matched_rules and #kong.ctx.plugin.ka_matched_rules > 0 then
      for _, matched in pairs(kong.ctx.plugin.ka_matched_rules) do
        if matched.rule.log then
          loggable_matches[#loggable_matches + 1] = matched
        end
      end
    end

    -- check if any sibling plugin queued external log entries
    local has_external_entries = false
    if kong.ctx.shared.karna
       and type(kong.ctx.shared.karna.log_entries) == "table"
       and #kong.ctx.shared.karna.log_entries > 0 then
      has_external_entries = true
    end

    -- skip logging if auditlog_only_on_match and no matches and no external entries
    if plugin_conf.auditlog_only_on_match
       and #loggable_matches == 0
       and not has_external_entries then
      return
    end

    local json_log = nil

    if plugin_conf.auditlog_format == "v2" then
      -- v2 format: structured JSON with all matches in a single log entry
      json_log = utils:get_auditlog_v2(loggable_matches, plugin_conf)
    else
      -- v1 format: legacy format (last matched rule wins)
      json_log = utils:get_auditlog(nil, nil)
      if #loggable_matches > 0 then
        local last_match = loggable_matches[#loggable_matches]
        json_log = utils:get_auditlog(last_match.rule, last_match.part)
      end

      if plugin_conf.auditlog_modsec then
        json_log["transaction"]["producer"] = {}
        if plugin_conf.engine_blocking_mode then
          json_log["transaction"]["producer"]["secrules_engine"] = "Enabled"
        else
          json_log["transaction"]["producer"]["secrules_engine"] = "DetectionOnly"
        end
      end
    end

    -- From a rule, it is possible to add additional log fields
    if kong.ctx.plugin.additional_log_fields then
      for alf_name, alf_value in pairs(kong.ctx.plugin.additional_log_fields) do
        json_log[alf_name] = engine:resolve_variable(alf_value)
      end
    end

    -- Redact MCP-sensitive fields (Authorization, MCP-Session-Id) before
    -- the async writer flushes the entry to disk. No-op if mcp_enabled=false
    -- or both redact toggles are off.
    if plugin_conf.mcp_enabled then
      ka_mcp.redact_audit(json_log, plugin_conf)
    end

    -- write log to file
    local timestamp = os.time(os.date("!*t"))
    local request_id = ngx.var.request_id
    ngx.timer.at(0, utils.write_auditlog, json_log, plugin_conf.auditlog_path, timestamp, request_id)
  end
end

return plugin


