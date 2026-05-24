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

local debug = kong.log.debug
local inspect = kong.log.inspect

-- Parse and cache the rules a specific plugin instance contributes
-- dynamically — i.e. CRS exclusion plugins loaded from disk
-- (`crs_plugins_enabled` entries under `crs_plugins_path/<name>/plugins/`)
-- and inline SecLang strings (`custom_secrules`). Keyed by
-- `tostring(plugin_conf)` because Kong gives us a stable table identity
-- per plugin-config record within a worker; reconfiguration
-- (Admin API write) produces a new table, which invalidates the cache.
local load_plugin_dynamic_rules = function(plugin_conf)
  local enabled = plugin_conf.crs_plugins_enabled or {}
  local inline = plugin_conf.custom_secrules or {}
  if #enabled == 0 and #inline == 0 then return {} end

  local out = {}

  local base_dir = plugin_conf.crs_plugins_path or "/opt/coreruleset-plugins/"
  if not base_dir:match("/$") then base_dir = base_dir .. "/" end

  for _, plugin_name in ipairs(enabled) do
    local plugin_dir = base_dir .. plugin_name .. "/plugins/"
    local files = seclang.collect_plugin_conf_files(plugin_dir)
    for fname, content in pairs(files) do
      local parsed = seclang.parse_isolated(content)
      local count = 0
      for _ in pairs(parsed) do count = count + 1 end
      debug("CRS plugin '" .. plugin_name .. "/" .. fname
            .. "' parsed " .. tostring(count) .. " rules")
      for _, r in pairs(parsed) do table.insert(out, r) end
    end
  end

  for idx, raw in ipairs(inline) do
    local parsed = seclang.parse_isolated(raw)
    local count = 0
    for _ in pairs(parsed) do count = count + 1 end
    debug("custom_secrules[" .. idx .. "] parsed "
          .. tostring(count) .. " rules")
    for _, r in pairs(parsed) do table.insert(out, r) end
  end

  return out
end

local get_plugin_dynamic_rules = function(plugin_conf)
  local key = "plugin_dyn_rules:" .. tostring(plugin_conf)
  local cached = ka_rules:get(key)
  if cached then return cached end
  local parsed = load_plugin_dynamic_rules(plugin_conf)
  ka_rules:set(key, parsed)
  return parsed
end

-- Side-effects of a matched rule's `rule_control` list onto the
-- per-request `kong.ctx.plugin.rule_controls`. Extracted so both the
-- standard evaluate_rules path (first-match-wins) and the CRS-plugins
-- multi-match path can apply controls without duplicating dispatch.
local apply_rule_controls = function(controls)
  if not controls then return end
  for _, control in pairs(controls) do
    if control.remove_rule and control.remove_rule.rule_id then
      local id_spec = control.remove_rule.rule_id
      local lo, hi = string.match(id_spec, "^(%d+)%-(%d+)$")
      if lo and hi then
        local lo_n, hi_n = tonumber(lo), tonumber(hi)
        if lo_n and hi_n then
          for n = lo_n, hi_n do
            kong.ctx.plugin.rule_controls.ids[tostring(n)] = { action = "remove" }
          end
        end
      else
        kong.ctx.plugin.rule_controls.ids[id_spec] = { action = "remove" }
      end
    end

    if control.remove_target_from_rule_by_id then
      local r = control.remove_target_from_rule_by_id
      if r.rule_id and r.target then
        if not kong.ctx.plugin.rule_controls.ids_targets[r.rule_id] then
          kong.ctx.plugin.rule_controls.ids_targets[r.rule_id] = {}
        end
        table.insert(kong.ctx.plugin.rule_controls.ids_targets[r.rule_id], r.target)
      end
    end

    if control.remove_target_rule_by_tag and control.remove_target_rule_by_tag.tag then
      local rt = control.remove_target_rule_by_tag
      if rt.tag == "OWASP_CRS" then
        table.insert(kong.ctx.plugin.rule_controls.remove_target_from_all_rules, rt.name)
      else
        if not kong.ctx.plugin.rule_controls.tags[rt.tag] then
          kong.ctx.plugin.rule_controls.tags[rt.tag] = {
            action = "remove_target",
            target = { rt.name }
          }
        else
          table.insert(kong.ctx.plugin.rule_controls.tags[rt.tag].target, rt.name)
        end
      end
    end

    if control.engine_off then
      kong.ctx.plugin.rule_controls.engine_off = true
    end
  end
end

-- Evaluate a pack of `pass`-action rules (CRS exclusion plugins +
-- `custom_secrules` whose actions are purely ctl:* / setvar:* side
-- effects), applying every matching rule's rule_control. Unlike the
-- standard `evaluate_rules` path this does NOT stop on first match
-- and does NOT honor fixed_response (those rules belong in the main
-- rule pool, evaluated through `loop_rules`).
local apply_pass_rule_controls = function(plugin_conf, rules, phase)
  if not rules or #rules == 0 then return end
  local matched = engine:loop_rule_controls_pass(plugin_conf, rules, phase)
  for _, rule in pairs(matched) do
    if rule.rule_control then
      apply_rule_controls(rule.rule_control)
    end
  end
end

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
            -- `rule_id` can be a single id ("920273") or a hyphen-range
            -- ("9507100-9507999") — CRS exclusion plugins use ranges to
            -- disable the entire id block when the plugin is opted out.
            local id_spec = control.remove_rule.rule_id
            local lo, hi = string.match(id_spec, "^(%d+)%-(%d+)$")
            if lo and hi then
              local lo_n = tonumber(lo)
              local hi_n = tonumber(hi)
              if lo_n and hi_n then
                for n = lo_n, hi_n do
                  kong.ctx.plugin.rule_controls.ids[tostring(n)] = { action = "remove" }
                end
              end
            else
              kong.ctx.plugin.rule_controls.ids[id_spec] = { action = "remove" }
            end
          end
        end

        -- ctl:ruleRemoveTargetById=<id>;<target> — drop a specific
        -- variable target from a specific rule, for this request only.
        -- Used heavily by CRS exclusion plugins (wordpress, drupal, …)
        -- to whitelist known-good arg/header names per app endpoint.
        if control.remove_target_from_rule_by_id then
          local r = control.remove_target_from_rule_by_id
          if r.rule_id and r.target then
            if not kong.ctx.plugin.rule_controls.ids_targets[r.rule_id] then
              kong.ctx.plugin.rule_controls.ids_targets[r.rule_id] = {}
            end
            table.insert(kong.ctx.plugin.rule_controls.ids_targets[r.rule_id], r.target)
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

        -- ctl:ruleEngine=Off — disable rule evaluation entirely for
        -- this request. Used by CRS exclusion plugins on endpoints
        -- that need to bypass the WAF (e.g. file-manager pages).
        if control.engine_off then
          kong.ctx.plugin.rule_controls.engine_off = true
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

  -- pre-validate request body parser (multipart hardening flags reject
  -- malformed payloads upstream of rule evaluation; without this gate
  -- the rejection produces an empty values table and slips through).
  engine:check_request_body_parser(plugin_conf)

  -- set local variables
  kong.ctx.plugin.rule_variables = {}

  -- set transaction variables (for setvar support + CRS-setup-style
  -- config knobs). Karna users configure via plugin_conf; we mirror the
  -- relevant values into the TX bag so CRS rules that read TX:<name>
  -- directly (e.g. 920250's `TX:CRS_VALIDATE_UTF8_ENCODING @eq 1`) get
  -- the expected gate value without requiring crs-setup.conf.
  -- Lowercase keys — seclang emits `tx:<lowercase>` for TX:<NAME> lookups.
  kong.ctx.plugin.tx_variables = {
    crs_validate_utf8_encoding = plugin_conf.validate_utf8_encoding and "1" or "0",
  }

  -- set rule controls — per-request store populated by rules whose
  -- `rule_control` action fires (CRS `ctl:*` directives end up here).
  --   ids[<rule_id>]                 = { action = "remove" }  → drop rule entirely for this request
  --   ids_targets[<rule_id>]         = { target1, target2 }   → drop these targets when <rule_id> evaluates
  --   tags[<tag>]                    = { action = "remove_target", target = [...] }
  --   remove_target_from_all_rules   = [target1, target2, …]  → drop globally for this request
  --   engine_off                     = bool                   → ctl:ruleEngine=Off; skips all subsequent rules
  kong.ctx.plugin.rule_controls = {
    ids = {},
    ids_targets = {},
    tags = {},
    remove_target_from_all_rules = {},
    engine_off = false,
  }

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

  -- CRS exclusion plugins + inline custom_secrules. Evaluated AFTER the
  -- built-in rule controls and BEFORE local + global rules so the
  -- ctl:* directives they emit populate `kong.ctx.plugin.rule_controls`
  -- in time to affect every subsequent rule's evaluation. Unlike the
  -- detection-rule path, this evaluator does NOT stop on first match
  -- — every matching pass-rule contributes its ctl:* side-effects
  -- (the wp-rule-exclusions plugin alone fires multiple rules per
  -- WordPress endpoint, each whitelisting a different ARGS target).
  local plugin_dyn_rules = get_plugin_dynamic_rules(plugin_conf)
  apply_pass_rule_controls(plugin_conf, plugin_dyn_rules, "access")

  kong.log.inspect(kong.ctx.plugin.rule_controls)

  -- loop local rules
  if plugin_conf.local_rules_enabled then
    evaluate_rules(plugin_conf, local_rules_request, "access")
  end

  -- loop the OWASP ModSecurity Core Rule Set rules
  if plugin_conf.coreruleset_enabled then
    evaluate_rules(plugin_conf, rules, "access")
  end

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


