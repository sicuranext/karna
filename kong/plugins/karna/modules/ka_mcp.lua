-- modules/ka_mcp.lua
--
-- MCP (Model Context Protocol) integration for Karna.
--
-- This is the request-side (Phase 1) implementation: detection, JSON-RPC
-- envelope parsing, variable namespace mapping, and audit log redaction.
-- Streaming response support (SSE reassembly, mcp_event phase, drop_event /
-- replace_event / terminate_stream / inject_event actions) lands in Phase 2
-- via modules/ka_mcp_sse.lua.
--
-- Spec reference: https://modelcontextprotocol.io/specification/2025-11-25
--
-- Transports recognised:
--   * "streamable_http"  — current standard (single endpoint, POST + GET)
--   * "http_sse_legacy"  — deprecated 2024-11-05 dual-endpoint transport;
--                          detected via MCP-Protocol-Version header but not
--                          parsed at the body level. Block via the schema
--                          flag mcp_block_legacy_sse_transport.

local cjson_safe = require "cjson.safe"
local sse        = require "kong.plugins.karna.ka_mcp_sse"

local _M = {}

local string_gmatch = string.gmatch
local string_gsub   = string.gsub
local string_lower  = string.lower
local string_match  = string.match
local table_insert  = table.insert
local table_concat  = table.concat
local type          = type
local tostring      = tostring
local tonumber      = tonumber
local pairs         = pairs
local ipairs        = ipairs
local pcall         = pcall

-- ------------------------------------------------------------
-- Internal helpers (exposed with leading underscore for testability)
-- ------------------------------------------------------------

-- Validate a decoded JSON-RPC 2.0 envelope.
-- Returns: ok (bool), kind ("request"|"notification"|"response"|"error"|nil), err (string|nil)
function _M._validate_jsonrpc(decoded)
    if type(decoded) ~= "table" then
        return false, nil, "envelope is not a JSON object"
    end
    if decoded.jsonrpc ~= "2.0" then
        return false, nil, "missing or non-2.0 jsonrpc field"
    end

    local has_method = type(decoded.method) == "string"
    local has_id     = decoded.id ~= nil
    local has_result = decoded.result ~= nil
    local has_error  = decoded.error ~= nil

    if has_method and has_id and not has_result and not has_error then
        return true, "request", nil
    end
    if has_method and not has_id and not has_result and not has_error then
        return true, "notification", nil
    end
    if has_id and has_result and not has_method and not has_error then
        return true, "response", nil
    end
    if has_id and has_error and not has_method and not has_result then
        return true, "error", nil
    end
    return false, nil, "ambiguous or invalid JSON-RPC shape"
end

-- Glob match for MCP method names. Patterns:
--   literal       — exact match
--   "tools/*"     — single-segment wildcard (no '/')
--   "tools/**"    — multi-segment wildcard ('/' allowed)
-- patterns may be a single string or an array of strings.
function _M._method_matches(method, patterns)
    if type(method) ~= "string" then return false end
    if type(patterns) == "string" then patterns = { patterns } end
    if type(patterns) ~= "table" then return false end

    for _, pat in ipairs(patterns) do
        if type(pat) == "string" and pat ~= "" then
            -- Escape Lua-pattern specials EXCEPT '*' (we handle * ourselves).
            local lpat = pat:gsub("([%-%.%+%[%]%(%)%^%$%%])", "%%%1")
            -- Order matters: ** placeholder first, then single *.
            lpat = lpat:gsub("%*%*", "\1"):gsub("%*", "[^/]*"):gsub("\1", ".*")
            if string_match(method, "^" .. lpat .. "$") then
                return true
            end
        end
    end
    return false
end

-- Walk a dotted path on a Lua table. "tool.arguments.path" -> tbl.tool.arguments.path
-- Numeric segments traverse arrays. Returns nil if the path doesn't resolve.
function _M._lookup_path(tbl, dotted)
    if type(tbl) ~= "table" or type(dotted) ~= "string" then return nil end
    local cur = tbl
    for segment in string_gmatch(dotted, "[^.]+") do
        if type(cur) ~= "table" then return nil end
        local n = tonumber(segment)
        if n ~= nil and cur[n] ~= nil then
            cur = cur[n]
        else
            cur = cur[segment]
        end
        if cur == nil then return nil end
    end
    return cur
end

-- ------------------------------------------------------------
-- DETECTION
-- ------------------------------------------------------------

-- Match a path against an mcp_routes pattern. Patterns are plain prefixes
-- by default (e.g. "/mcp"), but support the same glob syntax as method names
-- if the caller writes "/api/v*/mcp" or "/services/**/mcp".
local function path_matches_route(path, patterns)
    if type(patterns) ~= "table" or #patterns == 0 then return false end
    for _, pat in ipairs(patterns) do
        if type(pat) == "string" and pat ~= "" then
            -- Plain substring match for the simple case ("/mcp" matches "/api/mcp").
            if pat:find("[*]") == nil then
                if path:find(pat, 1, true) then return true end
            else
                if _M._method_matches(path, pat) then return true end
            end
        end
    end
    return false
end

-- Returns the detected transport ("streamable_http" | "http_sse_legacy") or nil.
-- Side effect: populates kong.ctx.plugin.mcp = { transport, protocol_version, session_id }.
function _M.detect(plugin_conf)
    if not plugin_conf or not plugin_conf.mcp_enabled then return nil end

    local headers   = kong.request.get_headers() or {}
    local proto_v   = headers["mcp-protocol-version"]
    local sess_id   = headers["mcp-session-id"]
    local origin    = headers["origin"]

    local matched = false

    -- 1. Explicit route match (preferred, low FP risk).
    if not matched and type(plugin_conf.mcp_routes) == "table" and #plugin_conf.mcp_routes > 0 then
        local path = ngx.var.uri or ""
        if path_matches_route(path, plugin_conf.mcp_routes) then
            matched = true
        end
    end

    -- 2. Header sniffing (cheap, very specific to MCP).
    if not matched and (proto_v ~= nil or sess_id ~= nil) then
        matched = true
    end

    -- 3. Optional heuristic: Accept: text/event-stream + JSON-RPC body.
    if not matched and plugin_conf.mcp_detection_heuristic then
        local accept = headers["accept"] or ""
        if accept:find("text/event-stream", 1, true) then
            local body = kong.request.get_raw_body()
            if body and body:find('"jsonrpc"', 1, true) then
                matched = true
            end
        end
    end

    if not matched then return nil end

    -- Transport classification. The 2024-11-05 spec is the legacy dual-endpoint
    -- HTTP+SSE transport; everything else (including absent header) is treated
    -- as streamable_http.
    local transport = "streamable_http"
    if proto_v == "2024-11-05" then
        transport = "http_sse_legacy"
    end

    kong.ctx.plugin.mcp = {
        transport        = transport,
        protocol_version = proto_v,
        session_id       = sess_id,
        origin           = origin,
    }
    return transport
end

-- ------------------------------------------------------------
-- REQUEST PARSING
-- ------------------------------------------------------------

-- Parses the JSON-RPC envelope from the request body and enriches
-- kong.ctx.plugin.mcp with method, id, params, message_kind, and
-- method-specific extracted fields (tool, resource, prompt, client).
-- Idempotent — safe to call once per request.
function _M.parse_request(plugin_conf)
    local mcp = kong.ctx.plugin.mcp
    if not mcp then return end

    local body = kong.request.get_raw_body()
    if not body or body == "" then
        -- Empty body = either a GET (server→client SSE channel) or a POST
        -- without payload. Nothing to parse.
        return
    end

    -- Keep a reference for the mcp_jsonrpc_valid operator. Not flattened
    -- into inspection_table — internal use only.
    mcp._raw = body

    local decoded = cjson_safe.decode(body)
    if type(decoded) ~= "table" then
        -- Malformed JSON — leave mcp.message_kind unset so mcp_jsonrpc_valid
        -- can match against an explicit "envelope is broken" rule.
        return
    end

    local valid, kind = _M._validate_jsonrpc(decoded)
    if not valid then
        return
    end

    mcp.message_kind = kind
    mcp.method       = decoded.method
    mcp.id           = decoded.id
    mcp.params       = decoded.params

    -- Method-specific extraction.
    local p = decoded.params
    if type(p) == "table" then
        if decoded.method == "tools/call" then
            mcp.tool = { name = p.name, arguments = p.arguments }
        elseif decoded.method == "resources/read" then
            mcp.resource = { uri = p.uri }
        elseif decoded.method == "prompts/get" then
            mcp.prompt = { name = p.name, arguments = p.arguments }
        elseif decoded.method == "initialize" then
            if type(p.clientInfo) == "table" then
                mcp.client = { name = p.clientInfo.name, version = p.clientInfo.version }
            end
            -- Initialize carries the negotiated protocolVersion in params,
            -- which may differ from the header (clients that don't yet have
            -- a session send it here).
            if p.protocolVersion and not mcp.protocol_version then
                mcp.protocol_version = p.protocolVersion
            end
        end
    end

    if kind == "error" and type(decoded.error) == "table" then
        mcp.error = { code = decoded.error.code, message = decoded.error.message }
    end

    -- Eagerly populate kong.ctx.plugin.inspection_table so access-phase
    -- rules can resolve mcp.* variables. get_inspection_table is only
    -- invoked in header_filter, which is too late for the request rules.
    -- Idempotent thanks to the mcp._inspected flag set by populate_inspection_table.
    kong.ctx.plugin.inspection_table = kong.ctx.plugin.inspection_table or {}
    _M.populate_inspection_table(kong.ctx.plugin.inspection_table)
end

-- ------------------------------------------------------------
-- VARIABLE NAMESPACE
-- ------------------------------------------------------------

-- Walks kong.ctx.plugin.mcp and inserts mcp.* entries into the
-- inspection_table, matching the format used by every other variable in
-- the engine: an array of single-key tables { ["<varname>"] = <stringvalue> }.
function _M.populate_inspection_table(insp)
    local mcp = kong.ctx.plugin.mcp
    if not mcp or type(insp) ~= "table" then return end
    -- Idempotent: parse_request populates eagerly in access phase so
    -- access-phase rules can see mcp.*; get_inspection_table also calls
    -- this in header_filter. The flag prevents double-insertion.
    if mcp._inspected then return end
    mcp._inspected = true

    local function add(key, val)
        if val == nil then return end
        if type(val) == "boolean" then
            val = val and "true" or "false"
        end
        table_insert(insp, { ["mcp." .. key] = tostring(val) })
    end

    add("transport",        mcp.transport)
    add("protocol_version", mcp.protocol_version)
    add("session_id",       mcp.session_id)
    add("origin",           mcp.origin)
    add("message_kind",     mcp.message_kind)
    add("method",           mcp.method)
    add("id",               mcp.id)
    add("is_streaming",     mcp.is_streaming)

    if mcp.tool then
        add("tool.name", mcp.tool.name)
        if type(mcp.tool.arguments) == "table" then
            for k, v in pairs(mcp.tool.arguments) do
                if type(v) == "table" then
                    -- Stringify nested structures so single-value operators
                    -- can still rx/contains over them. For dotted access into
                    -- nested tool args, write rules against `mcp.params.arguments.<path>`.
                    local enc = cjson_safe.encode(v)
                    add("tool.arguments." .. tostring(k), enc or "")
                else
                    add("tool.arguments." .. tostring(k), v)
                end
            end
        end
    end

    if mcp.resource then add("resource.uri",  mcp.resource.uri)  end
    if mcp.prompt   then add("prompt.name",   mcp.prompt.name)   end

    if mcp.client then
        add("client.name",    mcp.client.name)
        add("client.version", mcp.client.version)
    end
    if mcp.server then
        add("server.name",    mcp.server.name)
        add("server.version", mcp.server.version)
    end

    if mcp.error then
        add("error.code",    mcp.error.code)
        add("error.message", mcp.error.message)
    end

    -- Generic dotted flatten of params. Lets users target arbitrary fields:
    --   mcp.params.uri
    --   mcp.params.arguments.path
    --   mcp.params.messages.0.content.text
    if type(mcp.params) == "table" then
        local function walk(prefix, val)
            if type(val) ~= "table" then
                add(prefix, val)
                return
            end
            -- Detect array vs map cheaply: if #val > 0 it's array-ish.
            if #val > 0 then
                for i = 1, #val do
                    walk(prefix .. "." .. (i - 1), val[i])
                end
            else
                for k, v in pairs(val) do
                    walk(prefix .. "." .. tostring(k), v)
                end
            end
        end
        for k, v in pairs(mcp.params) do
            walk("params." .. tostring(k), v)
        end
    end
end

-- ------------------------------------------------------------
-- STREAMING RESPONSE — header_filter
-- ------------------------------------------------------------

-- Inspect upstream response headers. If Content-Type indicates SSE, mark
-- the request as streaming and arm the SSE reassembler. Idempotent.
function _M.header_filter(plugin_conf)
    local mcp = kong.ctx.plugin.mcp
    if not mcp then return end

    local ct = kong.response.get_header("content-type") or ""
    if ct:lower():find("text/event-stream", 1, true) then
        mcp.is_streaming = true
        mcp.sse = sse.new()
        -- Force chunked-style processing in body_filter: response_buffering
        -- defaults to true on routes, which buffers the entire body before
        -- handing it off; that defeats per-event evaluation. The operator
        -- should set response_buffering=false on MCP routes — we don't
        -- mutate it from here, just log a warning so misconfig surfaces.
    end
end

-- ------------------------------------------------------------
-- STREAMING RESPONSE — body_filter
-- ------------------------------------------------------------

-- Drives the reassembler, evaluates `mcp_event`-phase rules per complete
-- event, applies the streaming action set by a matching rule, and rewrites
-- the outgoing chunk via ngx.arg[1].
--
-- Streaming actions (set by rules via rule.action.mcp_event_action):
--   * type = "drop"       — silently swallow this event from the wire
--   * type = "replace"    — substitute event payload with action.data
--                           (and optional action.event_type / action.id)
--   * type = "terminate"  — emit a final synthetic event with
--                           action.event_type (default "error") and
--                           action.data, then set EOF; subsequent chunks
--                           are silently dropped
--   * type = "inject"     — emit an additional event (action.data /
--                           action.event_type) AFTER the matched event
--
-- `evaluate_rules` must be passed in by the caller (handler.lua) to avoid
-- a circular require with ka_engine.
function _M.body_filter(plugin_conf, evaluate_rules)
    local mcp = kong.ctx.plugin.mcp
    if not mcp or not mcp.is_streaming then return end

    local state = mcp.sse
    if not state then return end

    local chunk = ngx.arg[1]
    local eof   = ngx.arg[2]

    -- Bypass mode: cap exceeded earlier in the request; pass everything
    -- through untouched until the stream ends.
    if state.bypassed or state.terminated then
        if state.terminated then
            -- We already emitted the synthetic terminating event; mute the
            -- rest of the upstream stream.
            ngx.arg[1] = ""
        end
        return
    end

    -- Enforce buffer cap. The reassembler holds incomplete bytes in
    -- state.buffer; we don't know the final event size yet, so the cap is
    -- on accumulated unparsed bytes. Once exceeded, switch to passthrough.
    local cap = plugin_conf.mcp_max_stream_buffer_bytes
    if cap and cap > 0 and #(state.buffer or "") + #(chunk or "") > cap then
        kong.log.warn("[karna] MCP SSE buffer cap (" .. tostring(cap)
            .. " bytes) exceeded; switching this stream to passthrough.")
        state.bypassed = true
        -- Flush whatever was buffered so the client doesn't lose it.
        if state.buffer and state.buffer ~= "" then
            ngx.arg[1] = state.buffer .. (chunk or "")
            state.buffer = ""
        end
        return
    end

    local events = sse.feed(state, chunk or "",
                            plugin_conf.mcp_max_event_size_bytes)

    if #events == 0 then
        -- No complete event yet — emit nothing and wait for more chunks.
        -- The buffer retains the partial bytes inside `state`.
        ngx.arg[1] = ""
        return
    end

    -- mcp_event-phase rules: global pack first (same global-before-local
    -- precedence as the access phase; the pack snapshot is pinned in
    -- kong.ctx.plugin.global_rules by handler.lua's :access), then local
    -- rules from kong.ctx.plugin.local_rules (parsed from
    -- plugin_conf.rules_request).
    local mcp_event_rules = {}
    if kong.ctx.plugin.global_rules and kong.ctx.plugin.global_rules.mcp_event then
        for _, r in ipairs(kong.ctx.plugin.global_rules.mcp_event) do
            table_insert(mcp_event_rules, r)
        end
    end
    if kong.ctx.plugin.local_rules then
        for _, r in ipairs(kong.ctx.plugin.local_rules) do
            if r.phase == "mcp_event" then
                table_insert(mcp_event_rules, r)
            end
        end
    end
    local out = {}
    for _, ev in ipairs(events) do
        if ev.oversize then
            -- Too big to evaluate; emit as-is.
            table_insert(out, ev.raw .. "\n\n")
        else
            -- Publish event context for the rule loop.
            mcp.event = ev
            mcp.event_action = nil

            -- Invalidate the per-request variable cache for mcp.event.*
            -- so each event is evaluated against its own values rather
            -- than the first event's cached resolution.
            if kong.ctx.plugin.ka_variable_cache then
                for k in pairs(kong.ctx.plugin.ka_variable_cache) do
                    if type(k) == "string" and k:sub(1, 10) == "mcp.event." then
                        kong.ctx.plugin.ka_variable_cache[k] = nil
                    end
                end
            end

            if evaluate_rules and #mcp_event_rules > 0 then
                evaluate_rules(plugin_conf, mcp_event_rules, "mcp_event")
            end

            local act = mcp.event_action
            if act and act.type == "drop" then
                -- emit nothing
            elseif act and act.type == "replace" then
                table_insert(out, sse.serialize({
                    type  = act.event_type or ev.type,
                    id    = act.id or ev.id,
                    data  = act.data or "",
                }))
            elseif act and act.type == "terminate" then
                table_insert(out, sse.serialize({
                    type = act.event_type or "error",
                    data = act.data or "stream terminated by Karna",
                }))
                state.terminated = true
                ngx.arg[1] = table_concat(out)
                ngx.arg[2] = true  -- signal EOF to downstream
                return
            elseif act and act.type == "inject" then
                table_insert(out, ev.raw .. "\n\n")
                table_insert(out, sse.serialize({
                    type = act.event_type or "message",
                    data = act.data or "",
                }))
            else
                -- default: byte-perfect passthrough
                table_insert(out, ev.raw .. "\n\n")
            end
        end
        mcp.event = nil
        mcp.event_action = nil
    end

    ngx.arg[1] = table_concat(out)
end

-- ------------------------------------------------------------
-- AUDIT REDACTION
-- ------------------------------------------------------------

-- Mutates an audit log entry in-place to remove or truncate sensitive
-- MCP-related fields. Driven by:
--   plugin_conf.mcp_redact_authorization_in_audit  (default true)
--   plugin_conf.mcp_redact_session_id_in_audit     (default true)
function _M.redact_audit(audit_entry, plugin_conf)
    if type(audit_entry) ~= "table" or type(plugin_conf) ~= "table" then return end

    local redact_auth = plugin_conf.mcp_redact_authorization_in_audit
    local redact_sess = plugin_conf.mcp_redact_session_id_in_audit
    if not redact_auth and not redact_sess then return end

    local function walk(t)
        for k, v in pairs(t) do
            if type(v) == "table" then
                walk(v)
            elseif type(k) == "string" and type(v) == "string" then
                local kl = string_lower(k)
                if redact_auth and kl == "authorization" then
                    t[k] = "[REDACTED]"
                elseif redact_sess and (kl == "mcp-session-id" or kl == "x-mcp-session-id") then
                    if #v > 4 then
                        t[k] = v:sub(1, 4) .. "***"
                    else
                        t[k] = "***"
                    end
                end
            end
        end
    end
    walk(audit_entry)
end

return _M
