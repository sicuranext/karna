-- ka-unittest/mcp_sse_reassembly.lua
--
-- Pure-helper tests for ka_mcp_sse (chunk reassembly + event parsing).
-- Run from repo root:   lua ka-unittest/mcp_sse_reassembly.lua

package.path = "./kong/plugins/karna/modules/?.lua;" .. package.path

-- Stub cjson.safe with a minimal implementation so we don't need OpenResty.
package.preload["cjson.safe"] = function()
    return {
        decode = function(s)
            -- Tiny ad-hoc JSON decoder for the test cases. Only objects
            -- with string keys and string/number/boolean scalars supported.
            if type(s) ~= "string" then return nil end
            local trimmed = s:gsub("^%s+", ""):gsub("%s+$", "")
            if trimmed == "" or trimmed:sub(1,1) ~= "{" then return nil end
            local t = {}
            for k, v in trimmed:gmatch('"([^"]+)"%s*:%s*"([^"]*)"') do
                t[k] = v
            end
            for k, v in trimmed:gmatch('"([^"]+)"%s*:%s*(-?%d+%.?%d*)') do
                if t[k] == nil then t[k] = tonumber(v) end
            end
            return next(t) and t or nil
        end,
        encode = function() return "" end,
    }
end

local ok, sse = pcall(require, "ka_mcp_sse")
if not ok then io.stderr:write("FAIL load ka_mcp_sse: " .. tostring(sse) .. "\n"); os.exit(1) end

local failures = 0
local function check(label, cond)
    if cond then print("  PASS  " .. label) else print("  FAIL  " .. label); failures = failures + 1 end
end

print("== parse_event ==")
local ev = sse.parse_event("event: message\nid: 42\ndata: hello")
check("parse: type",   ev.type == "message")
check("parse: id",     ev.id == "42")
check("parse: data",   ev.data == "hello")

local ev2 = sse.parse_event("data: line1\ndata: line2")
check("parse: multi-line data joined with \\n", ev2.data == "line1\nline2")

local ev3 = sse.parse_event(": this is a comment\nevent: x\ndata: y")
check("parse: comments skipped", ev3.type == "x" and ev3.data == "y")

local ev4 = sse.parse_event("retry: 3000\ndata: foo")
check("parse: retry as number", ev4.retry == 3000)

local ev5 = sse.parse_event("data:no-space-after-colon")
check("parse: data without space after colon", ev5.data == "no-space-after-colon")

print("== feed (chunked reassembly) ==")
local state = sse.new()
local events = sse.feed(state, "event: a\ndata: 1\n\nevent: b\ndata: 2\n\n")
check("two events in one feed", #events == 2 and events[1].type == "a" and events[2].type == "b")

-- Chunk split mid-event
state = sse.new()
events = sse.feed(state, "event: a\nda")
check("partial: returns 0 events",       #events == 0)
events = sse.feed(state, "ta: 1\n\n")
check("partial: completes after rest",   #events == 1 and events[1].data == "1")

-- Multiple events with chunk boundary at separator
state = sse.new()
events = sse.feed(state, "event: a\ndata: 1\n")
check("boundary mid-separator: 0 events", #events == 0)
events = sse.feed(state, "\nevent: b\ndata: 2\n\n")
check("boundary mid-separator: completes", #events == 2)

-- CRLF separators
state = sse.new()
events = sse.feed(state, "event: a\r\ndata: 1\r\n\r\n")
check("CRLF separator",                  #events == 1 and events[1].data == "1")

-- Oversize event
state = sse.new()
local big = "data: " .. string.rep("x", 100) .. "\n\n"
events = sse.feed(state, big, 50)
check("oversize: marked",                #events == 1 and events[1].oversize == true)

-- JSON data auto-decode
state = sse.new()
events = sse.feed(state, 'data: {"method":"tools/call","id":1}\n\n')
check("JSON data decoded",               events[1].data_decoded and events[1].data_decoded.method == "tools/call")

-- terminated state ignores further chunks
state = sse.new()
state.terminated = true
events = sse.feed(state, "event: x\ndata: 1\n\n")
check("terminated: returns no events",   #events == 0)

print("== serialize ==")
local s = sse.serialize({ type = "alert", data = "boom" })
check("serialize includes event field",  s:find("event: alert", 1, true) ~= nil)
check("serialize includes data field",   s:find("data: boom",   1, true) ~= nil)
check("serialize ends with blank line",  s:sub(-2) == "\n\n")

local s2 = sse.serialize({ data = "multi\nline" })
check("serialize: multi-line data → multiple data: lines",
      s2:find("data: multi", 1, true) and s2:find("data: line", 1, true))

local s3 = sse.serialize({ type = "message", data = "x" })
check("serialize: default 'message' type omitted",
      s3:find("event:", 1, true) == nil)

if failures > 0 then
    io.stderr:write(("\n%d failure(s)\n"):format(failures))
    os.exit(1)
end
print("\nall green")
