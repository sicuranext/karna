-- modules/ka_mcp_sse.lua
--
-- Server-Sent Events (SSE) reassembler. Consumed by ka_mcp.body_filter to
-- turn nginx body_filter chunks into complete SSE events for rule evaluation.
--
-- Wire format reference: https://html.spec.whatwg.org/multipage/server-sent-events.html
--   * Events are separated by a blank line (CRLF CRLF or LF LF).
--   * Within an event, lines are `field: value` pairs.
--   * Fields: `event` (type, default "message"), `id`, `data` (may repeat,
--     joined with \n), `retry` (milliseconds).
--   * Lines starting with `:` are comments and MUST be ignored.
--
-- For MCP-over-streamable-HTTP, the SSE `data:` field carries the JSON-RPC
-- payload (request, notification, response or error). ka_mcp_sse only parses
-- the SSE envelope; JSON-RPC decoding stays in ka_mcp.

local cjson_safe = require "cjson.safe"

local _M = {}

local string_find = string.find
local string_sub  = string.sub
local string_gsub = string.gsub
local string_gmatch = string.gmatch
local tonumber = tonumber
local tostring = tostring
local table_concat = table.concat
local table_insert = table.insert

-- ------------------------------------------------------------
-- Per-request state
-- ------------------------------------------------------------

-- Returns a fresh state object. Held in kong.ctx.plugin.mcp.sse for the
-- lifetime of the request.
function _M.new()
    return {
        buffer       = "",     -- bytes received but not yet forming a complete event
        buffer_bytes = 0,      -- soft running total used for the buffer cap check
        bypassed     = false,  -- once cap exceeded, switch to passthrough mode
        terminated   = false,  -- set by a terminate_stream action; ignore further chunks
    }
end

-- ------------------------------------------------------------
-- Parsing
-- ------------------------------------------------------------

-- Parse a single raw event text (no trailing separator) into a structured
-- event. Comments are ignored. `data` field collected across multiple lines
-- and joined with a literal newline per spec.
function _M.parse_event(raw)
    local ev = { type = "message" }
    local data_lines = {}
    for line in string_gmatch(raw, "[^\n]+") do
        line = string_gsub(line, "\r$", "")
        if line ~= "" and string_sub(line, 1, 1) ~= ":" then
            local colon = string_find(line, ":", 1, true)
            local field, val
            if colon then
                field = string_sub(line, 1, colon - 1)
                val   = string_sub(line, colon + 1)
                if string_sub(val, 1, 1) == " " then
                    val = string_sub(val, 2)
                end
            else
                field = line
                val   = ""
            end
            if field == "event" then
                ev.type = val
            elseif field == "id" then
                ev.id = val
            elseif field == "data" then
                table_insert(data_lines, val)
            elseif field == "retry" then
                ev.retry = tonumber(val)
            end
        end
    end
    ev.data = table_concat(data_lines, "\n")
    return ev
end

-- ------------------------------------------------------------
-- Reassembly
-- ------------------------------------------------------------

-- Append a chunk and return any complete events that emerged.
-- `max_event_size` caps a single event; oversize events are kept as raw
-- (passthrough, never matched against rules) to avoid memory blow-up on
-- pathological producers.
-- Returns: events (array), where each event is either parsed (with .data,
-- .type, .id, .retry, .raw) or `{ oversize = true, raw = "..." }`.
function _M.feed(state, chunk, max_event_size)
    if state.bypassed or state.terminated then
        return {}
    end
    if chunk == nil or chunk == "" then
        return {}
    end

    state.buffer = state.buffer .. chunk
    state.buffer_bytes = #state.buffer

    local events = {}
    while true do
        local sep_start, sep_end = string_find(state.buffer, "\r?\n\r?\n", 1)
        if not sep_start then break end
        local raw = string_sub(state.buffer, 1, sep_start - 1)
        state.buffer = string_sub(state.buffer, sep_end + 1)
        state.buffer_bytes = #state.buffer

        if max_event_size and max_event_size > 0 and #raw > max_event_size then
            table_insert(events, { oversize = true, raw = raw })
        else
            local ev = _M.parse_event(raw)
            ev.raw = raw
            -- If `data` looks like JSON, decode it once for cheap json-path
            -- access from rules. Best-effort: errors are silently ignored.
            if ev.data and string_sub(ev.data, 1, 1) == "{" then
                ev.data_decoded = cjson_safe.decode(ev.data)
            end
            table_insert(events, ev)
        end
    end

    return events
end

-- ------------------------------------------------------------
-- Serialization (for replace_event / inject_event actions)
-- ------------------------------------------------------------

-- Build wire-format event bytes from a structured event-like table.
-- Used by ka_mcp.body_filter when constructing synthetic events.
function _M.serialize(ev)
    if type(ev) ~= "table" then return "" end
    local parts = {}
    if ev.type and ev.type ~= "" and ev.type ~= "message" then
        table_insert(parts, "event: " .. tostring(ev.type))
    end
    if ev.id then
        table_insert(parts, "id: " .. tostring(ev.id))
    end
    if ev.retry then
        table_insert(parts, "retry: " .. tostring(ev.retry))
    end
    if ev.data ~= nil then
        local d = tostring(ev.data)
        -- One `data:` line per LF in the payload, per spec.
        for line in string_gmatch(d .. "\n", "([^\n]*)\n") do
            table_insert(parts, "data: " .. line)
        end
    end
    return table_concat(parts, "\n") .. "\n\n"
end

return _M
