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
local ka_compile        = require "kong.plugins.karna.ka_compile"
local lrucache          = require "resty.lrucache"
local cjson             = require "cjson"
local ipmatcher         = require "resty.ipmatcher"

local ka_rules, err = lrucache.new(10000)

local debug = kong.log.debug

-- Captured once at module load. When unset (production default) the
-- profiling trigger in the access phase is dead code.
local _KARNA_PROFILE_ENABLED = os.getenv("KARNA_PROFILE") ~= nil

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
  -- Compile dynamic rules into closures before caching. plugin_conf is
  -- passed so private_debug source dumps respect the per-service flag.
  -- See ka_compile.compile_rule for the contract.
  ka_compile.compile_rules(parsed, plugin_conf)
  ka_rules:set(key, parsed)
  return parsed
end

-- Parse + compile the rules carried inline by `plugin_conf.rules_request`
-- (JSON strings authored by service operators). Keyed on plugin_conf
-- table identity — Kong creates a new plugin_conf table on every Admin
-- API update, which invalidates the cache automatically. Previously
-- cjson.decode ran twice per rule per request (pcall validate + actual
-- decode); now it runs once per (worker, plugin_conf) lifetime.
-- The returned table carries two views:
--   .all    : every parsed rule, used as the cross-phase
--             kong.ctx.plugin.local_rules (header_filter / body_filter
--             / mcp_event filter by .phase).
--   .access : the subset whose .phase == "access", consumed directly
--             by the access-phase rule loop.
local get_local_request_rules = function(plugin_conf)
  if not plugin_conf.rules_request or #plugin_conf.rules_request == 0 then
    return { all = {}, access = {} }
  end
  local key = "local_request_rules:" .. tostring(plugin_conf)
  local cached = ka_rules:get(key)
  if cached then return cached end

  local all = {}
  local access = {}
  for _, req_rule_raw in pairs(plugin_conf.rules_request) do
    local ok, req_rule_or_err = pcall(cjson.decode, req_rule_raw)
    if ok then
      table.insert(all, req_rule_or_err)
      if req_rule_or_err.phase == "access" then
        table.insert(access, req_rule_or_err)
      end
    else
      kong.log.err("Error parsing JSON rule: " .. tostring(req_rule_or_err))
    end
  end

  ka_compile.compile_rules(all, plugin_conf)

  local result = { all = all, access = access }
  ka_rules:set(key, result)
  return result
end

-- Lightweight `%{var}` resolver for access-phase callers that need to
-- resolve a small set of request-context macros (rate_limit key,
-- response override body) without paying the cost of the full
-- inspection_table parser (which eagerly reads the request body and
-- has measurable PL1 side effects when invoked early). Falls back to
-- leaving unrecognised macros literal — same fail-soft posture as
-- engine:replace_variable_in_string when its inspection_table is
-- empty. Supported macros today:
--   %{remote_addr}     — ngx.var.remote_addr (Kong-visible client IP)
--   %{request.method}  — HTTP method
--   %{request.host}    — Host header
--   %{request.scheme}  — http / https
--   %{request.path}    — raw path (no querystring)
-- Anything else stays literal.
local resolve_request_macros = function(str)
  if type(str) ~= "string" then return str end
  -- Cheap early-out for the common case of no macros at all. The
  -- 2-character `%{` substring is what gsub's pattern matches; we
  -- pass plain=true so the search is a literal byte-match (a
  -- previous version used `%%{` which is actually the 3-character
  -- sequence `%`,`%`,`{` and silently skipped every callsite).
  if not str:find("%{", 1, true) then return str end

  local resolvers = {
    ["remote_addr"]    = function() return tostring(ngx.var.remote_addr or "") end,
    ["request.method"] = function() return tostring(kong.request.get_method() or "") end,
    ["request.host"]   = function() return tostring(kong.request.get_host() or "") end,
    ["request.scheme"] = function() return tostring(kong.request.get_scheme() or "") end,
    ["request.path"]   = function() return tostring(kong.request.get_path() or "") end,
  }
  return (str:gsub("%%{([^}]+)}", function(name)
    local fn = resolvers[name]
    if fn then return fn() end
    return "%{" .. name .. "}"  -- leave literal
  end))
end

-- Selector grammar for `rule_action_overrides` / `rule_response_overrides`.
-- `selector` matches when ANY positive criterion (ids / id_ranges / tags)
-- matches AND no `except_*` criterion matches. Empty positive set means
-- "match everything" — useful for "override default for all rules".
local selector_matches = function(selector, rule)
  if not selector or not rule then return false end

  -- except_* short-circuits negative.
  if selector.except_ids and rule.id then
    for _, eid in ipairs(selector.except_ids) do
      if tostring(eid) == tostring(rule.id) then return false end
    end
  end
  if selector.except_tags and rule.tags then
    for _, etag in ipairs(selector.except_tags) do
      for _, rtag in ipairs(rule.tags) do
        if rtag == etag then return false end
      end
    end
  end

  -- positive: if no positive criteria, the selector matches everything
  -- that wasn't excluded above. Useful for "fix every rule except …".
  local has_positive = (selector.ids and #selector.ids > 0)
                    or (selector.id_ranges and #selector.id_ranges > 0)
                    or (selector.tags and #selector.tags > 0)
                    or (selector.any == true)
  if not has_positive then return false end
  if selector.any == true then return true end

  if selector.ids and rule.id then
    for _, sid in ipairs(selector.ids) do
      if tostring(sid) == tostring(rule.id) then return true end
    end
  end
  if selector.id_ranges and rule.id then
    local rule_id_n = tonumber(rule.id)
    if rule_id_n then
      for _, rng in ipairs(selector.id_ranges) do
        local lo, hi = string.match(rng, "^(%d+)%-(%d+)$")
        if lo and hi and rule_id_n >= tonumber(lo) and rule_id_n <= tonumber(hi) then
          return true
        end
      end
    end
  end
  if selector.tags and rule.tags then
    for _, stag in ipairs(selector.tags) do
      for _, rtag in ipairs(rule.tags) do
        if rtag == stag then return true end
      end
    end
  end

  return false
end

-- Lazy-parse + cache the two override arrays per plugin_conf identity.
-- Same caching scheme as `get_plugin_dynamic_rules`: keyed on
-- `tostring(plugin_conf)` (worker-stable table address); Admin API
-- reconfig invalidates the cache automatically by producing a new
-- plugin_conf table.
local DEFAULT_FIX_PATTERN = [=[[<>"';&|`$()]]=]

local get_overrides_cached = function(plugin_conf)
  local key = "overrides:" .. tostring(plugin_conf)
  local cached = ka_rules:get(key)
  if cached then return cached end

  local out = { action_overrides = {}, response_overrides = {} }

  for _, raw in ipairs(plugin_conf.rule_action_overrides or {}) do
    local ok, parsed = pcall(cjson.decode, raw)
    if ok and type(parsed) == "table" and parsed.selector and parsed.action then
      table.insert(out.action_overrides, parsed)
    else
      kong.log.err("[karna] invalid rule_action_overrides entry: " .. tostring(raw):sub(1, 200))
    end
  end

  for _, raw in ipairs(plugin_conf.rule_response_overrides or {}) do
    local ok, parsed = pcall(cjson.decode, raw)
    if ok and type(parsed) == "table" and parsed.selector and parsed.response then
      table.insert(out.response_overrides, parsed)
    else
      kong.log.err("[karna] invalid rule_response_overrides entry: " .. tostring(raw):sub(1, 200))
    end
  end

  ka_rules:set(key, out)
  return out
end

-- Apply config-level overrides on top of the rule's declared action.
-- Returns a fresh `action` table (or the original reference if no
-- override matched). NEVER mutates the cached rule. The caller is
-- expected to swap the action on a shallow copy of rule_matched_obj
-- so downstream branches (sanitize dispatch, audit log) see the
-- effective behaviour.
local apply_action_and_response_overrides = function(plugin_conf, rule)
  local overrides = get_overrides_cached(plugin_conf)
  local n_a = #overrides.action_overrides
  local n_r = #overrides.response_overrides
  if n_a == 0 and n_r == 0 then return rule.action end

  local effective = rule.action

  -- action override (first matching wins)
  if n_a > 0 then
    for _, ov in ipairs(overrides.action_overrides) do
      if selector_matches(ov.selector, rule) then
        local t = ov.action and ov.action.type
        if t == "fix" then
          effective = {
            fix_matched_parts = {
              remove_chars_pattern = ov.action.remove_chars_pattern or DEFAULT_FIX_PATTERN,
            },
          }
        elseif t == "passthrough" then
          effective = { setvar = {} }
        elseif t == "block" then
          local base = (rule.action and rule.action.fixed_response) or {
            status_code = 403,
            body = "Forbidden\r\n",
            headers = { ["content-type"] = "text/plain" },
          }
          effective = { fixed_response = {
            status_code = base.status_code,
            body = base.body,
            headers = base.headers,
          } }
        end
        break
      end
    end
  end

  -- response override (customises body/status/headers if action is block)
  if n_r > 0 and effective and effective.fixed_response then
    for _, ov in ipairs(overrides.response_overrides) do
      if selector_matches(ov.selector, rule) then
        local fr = effective.fixed_response
        -- ensure we own the fixed_response table — it may still point
        -- at the cached rule's original when no action override fired.
        local new_fr = {
          status_code = fr.status_code,
          body = fr.body,
          headers = {},
        }
        if fr.headers then
          for k, v in pairs(fr.headers) do new_fr.headers[k] = v end
        end
        if ov.response.status_code then new_fr.status_code = ov.response.status_code end
        if ov.response.body then
          new_fr.body = resolve_request_macros(ov.response.body)
        end
        if ov.response.headers then
          for k, v in pairs(ov.response.headers) do new_fr.headers[k] = v end
        end
        effective = { fixed_response = new_fr }
        if rule.action and rule.action.setvar then effective.setvar = rule.action.setvar end
        if rule.action and rule.action.fix_matched_parts then effective.fix_matched_parts = rule.action.fix_matched_parts end
        break
      end
    end
  end

  return effective
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

    -- Apply config-level action / response overrides. The original
    -- rule object stays immutable — we shallow-copy and swap `.action`
    -- so the rest of the dispatch (sanitize, fixed_response, audit
    -- log) sees the effective behaviour. No-op (returns the original
    -- action reference) when no override matches this rule.
    if rule_matched_obj.action then
      local effective_action = apply_action_and_response_overrides(plugin_conf, rule_matched_obj)
      if effective_action ~= rule_matched_obj.action then
        local copy = {}
        for k, v in pairs(rule_matched_obj) do copy[k] = v end
        copy.action = effective_action
        rule_matched_obj = copy
      end
    end

    -- Record the match so the log phase can surface it in audit log v2.
    -- Without this, only the always-on gate violations (method/path/CT)
    -- showed up in the v2 `matches[]` array; standard rule matches were
    -- silently swallowed when blocking-mode response_exit'd. We populate
    -- here once and let the downstream branches mutate `sanitized` /
    -- response details before the log phase reads it.
    local match_entry = {
      rule = rule_matched_obj,
      part = matches_info,
      sanitized = false,
    }
    table.insert(kong.ctx.plugin.ka_matched_rules, match_entry)

    -- sanitize-not-block: when a rule carries a `fix_matched_parts`
    -- action, Karna strips dangerous characters from the matched
    -- targets in-place and lets the request continue to upstream. This
    -- is the killer FP-mitigation: a payload that looks like SQLi/XSS
    -- but is actually a proper name ("O'Brien") or a street address
    -- ("Via dell'Orso, 5") goes through with the unsafe characters
    -- removed. Takes precedence over `fixed_response` when both are
    -- declared on the same rule — sanitize wins because it preserves
    -- the user journey.
    if rule_matched_obj.action and rule_matched_obj.action.fix_matched_parts and matches_info then
      engine:__fix_matching_parts(rule_matched_obj, matches_info)
      match_entry.sanitized = true
      -- skip the block branch; sanitize already mutated the upstream
      -- request and the response should be whatever upstream returns.
      return
    end

    -- Rate-limit action: when a rule with `rate_limit` declared on its
    -- action fires, Karna increments a Redis counter keyed by the
    -- rule id + the resolved `key` macro (default `%{remote_addr}`),
    -- sets a TTL = `window_seconds` the first time the counter is
    -- created (fixed-window semantics), and:
    --   - if the post-incr count exceeds `limit` → respond with the
    --     configured response (defaults to 429 Too Many Requests).
    --   - otherwise → request continues to upstream as if the rule
    --     hadn't fired.
    -- Counter increments happen regardless of engine_blocking_mode
    -- (detection-only dry runs are useful for tuning thresholds);
    -- the terminal 429 only fires when blocking is on.
    if rule_matched_obj.action and rule_matched_obj.action.rate_limit then
      local rl = rule_matched_obj.action.rate_limit
      local limit = tonumber(rl.limit) or 0
      local window = tonumber(rl.window_seconds) or 60
      local key_macro = rl.key
      if type(key_macro) ~= "string" or key_macro == "" then
        key_macro = "%{remote_addr}"
      end
      local resolved_key = resolve_request_macros(key_macro)
      local full_key = "karna:rl:" .. tostring(rule_matched_obj.id) .. ":" .. tostring(resolved_key)

      utils.redis_host = plugin_conf.redis_host
      utils.redis_port = plugin_conf.redis_port
      utils.redis_password = plugin_conf.redis_password

      local count = utils:redis_incr_key(full_key, window)
      match_entry.rate_limit_count = count
      match_entry.rate_limit_limit = limit
      match_entry.rate_limit_window = window
      match_entry.rate_limit_key = full_key
      match_entry.rate_limited = (count ~= nil and limit > 0 and count > limit)

      if plugin_conf.engine_blocking_mode and match_entry.rate_limited then
        local resp = rl.response or {}
        local headers = resp.headers
        if type(headers) ~= "table" then
          headers = { ["content-type"] = "text/plain", ["cache-control"] = "no-store" }
        end
        if not headers["retry-after"] and not headers["Retry-After"] then
          headers["Retry-After"] = tostring(window)
        end
        response_exit(
          tonumber(resp.status_code) or 429,
          resp.body or "Too Many Requests\r\n",
          headers
        )
      end
      -- Counter has been bumped; the rule's role for this request is
      -- done. Skip the standard block / control branches below.
      return
    end

    -- if blocking mode enabled, exit with error
    if plugin_conf.engine_blocking_mode then
      if rule_matched_obj.action then

        if rule_matched_obj.action.fixed_response then
          if plugin_conf.private_debug then
            -- Echo the matched rule id in a response header as well.
            -- The JSON body in `private_debug` mode carries the same
            -- info, but HTTP HEAD responses strip the body — the header
            -- is the only channel that survives, so test harnesses
            -- (CRS regression suite) can identify which rule fired
            -- regardless of method.
            local dbg_headers = rule_matched_obj.action.fixed_response.headers
              or { ["content-type"] = "text/plain", ["cache-control"] = "max-age=0, private, no-store, no-cache, must-revalidate" }
            if rule_matched_obj.id then
              dbg_headers["x-karna-rule-id"] = tostring(rule_matched_obj.id)
            end
            response_exit(
              rule_matched_obj.action.fixed_response.status_code or 403,
              cjson.encode(rule_matched_obj),
              dbg_headers
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

  -- jit.p profiling trigger — only active when KARNA_PROFILE env is
  -- set on the worker (so this is a literal no-op in production: the
  -- os.getenv result is captured once at module load). Drive it with:
  --   X-Karna-Profile: start  → begin LuaJIT sampling profiler
  --   X-Karna-Profile: stop   → stop + flush report to
  --                             /tmp/karna-jitp.txt
  -- Run with KONG_NGINX_WORKER_PROCESSES=1 so all load hits the one
  -- worker the profiler is attached to.
  if _KARNA_PROFILE_ENABLED then
    local pdir = kong.request.get_header("x-karna-profile")
    if pdir == "start" then
      require("jit.p").start("3Fli", "/tmp/karna-jitp.txt")
      return kong.response.exit(200, "profile started\n")
    elseif pdir == "stop" then
      pcall(function() require("jit.p").stop() end)
      return kong.response.exit(200, "profile stopped\n")
    end
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

  -- DoS guard: cap arguments (query + urlencoded + multipart parts + JSON
  -- keys) at limit_arg_num. The body is parsed+cached above, so counting
  -- is cheap; over the limit we skip the ~160-rule scan (the real cost).
  -- In blocking mode this already returned 403; the flag only matters in
  -- detection mode, where we still skip the scan so a pathological request
  -- can't pin the worker.
  local ka_arg_limit_exceeded = engine:check_request_arg_count(plugin_conf)

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

  -- get service local request rules from the per-plugin_conf cache.
  -- The cache carries both the full list (for cross-phase consumption
  -- via kong.ctx.plugin.local_rules) and the access-phase subset.
  -- See get_local_request_rules for the cache key + parse contract.
  local local_request_rules_cache = get_local_request_rules(plugin_conf)
  kong.ctx.plugin.local_rules = local_request_rules_cache.all
  local local_rules_request = local_request_rules_cache.access

  -- Over the argument-count limit (detection mode): the body parsed clean
  -- but carries more args than limit_arg_num. Skip all rule evaluation —
  -- scanning a pathological request is the DoS. Setup above (local_rules,
  -- tx_variables) already ran so later phases stay consistent; the
  -- violation is recorded in ka_matched_rules for the audit log.
  if ka_arg_limit_exceeded then
    return
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


