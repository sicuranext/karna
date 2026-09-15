-- ka-unittest/macro_resolution_phases.lua
--
-- Guards the `%{var}` macro resolvers used by the rule ACTIONS against a
-- silent-failure bug: in the access phase they resolved nothing.
--
-- `redis_incr_key` and `set_variable` resolve their key / value through
-- `engine:replace_variable_in_string`, which looked every macro up in
-- `kong.ctx.plugin.inspection_table`. That table is built by
-- `get_inspection_table`, whose only caller is handler.lua's `header_filter`.
-- In `access` it is nil, so every macro stayed LITERAL and the action wrote a
-- key containing the raw text `%{remote_addr}`.
--
-- The read half of the same feature never had the problem: the `redis.<key>`
-- inspection variable resolves its key with `__resolve_redis_key_macros`,
-- which reads the request directly and therefore works in every phase. So the
-- documented "roll your own rate limit" idiom — a non-terminal rule with
-- `redis_incr_key` on `counter:%{remote_addr}`, plus a terminal rule whose
-- condition reads `redis.counter:%{remote_addr}` — incremented
--
--     counter:%{remote_addr}      one bucket shared by every client
--
-- and read
--
--     counter:203.0.113.7         a key nothing ever created
--
-- so the threshold could never be crossed. No error, no warning: the shared
-- counter just sat above the limit while nothing was throttled.
--
-- `replace_variable_in_string` now resolves the request-context macros first
-- (through the same `__resolve_redis_key_macros` the reader uses) and only
-- then consults the inspection table for the richer variables.
--
-- What is pinned here, driven through the REAL engine:
--   1. in access (inspection_table nil) the write resolver and the read
--      resolver produce the SAME string for the same template;
--   2. the whole request-context macro set resolves in access;
--   3. the real `redis_incr_key` action dispatch increments the resolved key,
--      and it is byte-identical to the key the `redis.<key>` reader derives
--      from the same template;
--   4. `set_variable` with a `%{...}` value stores the VALUE, not the template;
--   5. header_filter behaviour is unchanged — inspection-table variables still
--      resolve, and the request-context macros resolve to the same value they
--      did when they came from the table;
--   6. an unknown macro is still left literal (fail-soft, no crash);
--   7. a resolved value containing `%` does not blow up the gsub.
--
-- Fixtures are synthetic.
--
-- Run from repo root:
--   lua    ka-unittest/macro_resolution_phases.lua
--   luajit ka-unittest/macro_resolution_phases.lua

local H = dofile("./ka-unittest/_engine_harness.lua")
local engine = H.engine
local utils  = require "kong.plugins.karna.ka_utils"

local fails = 0
local function ok(cond, name, detail)
    if cond then print("  ok  - " .. name)
    else print("  FAIL- " .. name .. (detail and ("  (" .. tostring(detail) .. ")") or "")); fails = fails + 1 end
end

local function eq(got, want, name)
    ok(got == want, name, "got " .. tostring(got) .. ", want " .. tostring(want))
end

-- The harness request: remote_addr 192.0.2.10, GET http://app.example/
local function fresh_access_request()
    H.reset()
    H.request.method  = "POST"
    H.request.path    = "/login"
    H.request.headers = { Host = "app.example", ["X-Consumer-Id"] = "acme-42" }
    -- access phase: nothing has built the inspection table yet
    kong.ctx.plugin.inspection_table = nil
end

-- ---------------------------------------------------------------------------
-- 1. write resolver == read resolver, in the access phase
-- ---------------------------------------------------------------------------
print("\n-- access phase: the write path and the read path agree on a key --")

fresh_access_request()
ok(kong.ctx.plugin.inspection_table == nil,
   "precondition: the inspection table does not exist in access")

local TEMPLATE = "counter:60s:%{remote_addr}"
local written = engine:replace_variable_in_string(TEMPLATE)
local read    = engine:__resolve_redis_key_macros(TEMPLATE)

eq(written, "counter:60s:192.0.2.10",
   "replace_variable_in_string resolves %{remote_addr} in access")
eq(read, "counter:60s:192.0.2.10",
   "__resolve_redis_key_macros resolves %{remote_addr} in access (unchanged)")
eq(written, read,
   "write key and read key are byte-identical for the same template")
ok(not written:find("%%{", 1, true),
   "no literal %{...} survives into the written key")

-- ---------------------------------------------------------------------------
-- 2. the whole request-context macro set
-- ---------------------------------------------------------------------------
print("\n-- access phase: every request-context macro --")

local cases = {
    { "%{remote_addr}",                   "192.0.2.10" },
    { "%{request.method}",                "POST"       },
    { "%{request.host}",                  "app.example"},
    { "%{request.scheme}",                "http"       },
    { "%{request.path}",                  "/login"     },
    { "%{request_headers.x-consumer-id}", "acme-42"    },
}
for _, c in ipairs(cases) do
    fresh_access_request()
    local w = engine:replace_variable_in_string("k:" .. c[1])
    local r = engine:__resolve_redis_key_macros("k:" .. c[1])
    eq(w, "k:" .. c[2], c[1] .. " resolves in access (write path)")
    eq(w, r, c[1] .. " agrees with the read path")
end

-- %{connection.id} is pinned into the plugin ctx by ka_tls.populate at the top
-- of access, so it resolves there too. It is documented as a rate_limit key
-- macro ("one counter per connection"), which only works if it resolves in the
-- phase rate_limit runs in.
fresh_access_request()
kong.ctx.plugin.connection_id = "kc1_deadbeefdeadbeefdeadbeefdeadbeef"
eq(engine:replace_variable_in_string("c:%{connection.id}"),
   "c:kc1_deadbeefdeadbeefdeadbeefdeadbeef",
   "%{connection.id} resolves in access (write path)")
eq(engine:__resolve_redis_key_macros("c:%{connection.id}"),
   "c:kc1_deadbeefdeadbeefdeadbeefdeadbeef",
   "%{connection.id} agrees with the read path")

-- absent (connection ids disabled / ka_tls.init failed): LITERAL, never empty.
-- An empty segment would fold every client into one shared counter key.
fresh_access_request()
kong.ctx.plugin.connection_id = nil
eq(engine:replace_variable_in_string("c:%{connection.id}"), "c:%{connection.id}",
   "an unavailable connection id leaves the macro literal, not empty")

-- a template mixing several macros
fresh_access_request()
eq(engine:replace_variable_in_string("rl:%{request.method}:%{request.path}:%{remote_addr}"),
   "rl:POST:/login:192.0.2.10",
   "several macros in one template all resolve")

-- ---------------------------------------------------------------------------
-- 3. the real redis_incr_key action dispatch
-- ---------------------------------------------------------------------------
print("\n-- access phase: the real redis_incr_key action --")

-- Capture what the action hands to Redis. `utils` here is the very table the
-- engine holds, so this intercepts the real call site without touching any
-- Kong global.
local real_incr = utils.redis_incr_key
local incr_calls = {}
utils.redis_incr_key = function(_, key, expire)
    incr_calls[#incr_calls + 1] = { key = key, expire = expire }
    return #incr_calls
end

local plugin_conf = {
    engine_fast_path = true,
    redis_host = "127.0.0.1", redis_port = 6379, redis_password = nil,
}

fresh_access_request()
incr_calls = {}
engine:apply_action_side_effects({
    id = "local_counter", phase = "access",
    action = { redis_incr_key = { key = "failed_login_attempts:%{remote_addr}", expire = 300 } },
}, plugin_conf, "access")

ok(#incr_calls == 1, "the action reached Redis exactly once", "calls=" .. #incr_calls)
eq(incr_calls[1] and incr_calls[1].key, "failed_login_attempts:192.0.2.10",
   "redis_incr_key increments the RESOLVED key in access")
eq(incr_calls[1] and incr_calls[1].key,
   engine:__resolve_redis_key_macros("failed_login_attempts:%{remote_addr}"),
   "the incremented key is exactly the key the redis.<key> reader looks up")

-- the same rule in header_filter (where the idiom is documented) must keep
-- producing the same key, not a different one
H.reset()
H.request.method  = "POST"
H.request.path    = "/login"
H.request.headers = { Host = "app.example" }
kong.ctx.plugin.inspection_table = { { ["remote_addr"] = "192.0.2.10" } }
incr_calls = {}
local scheduled = 0
local real_timer_at = ngx.timer.at
ngx.timer.at = function(_, fn, self_, conf_, key_, exp_)
    scheduled = scheduled + 1
    incr_calls[#incr_calls + 1] = { key = key_, expire = exp_ }
    return true
end
engine:apply_action_side_effects({
    id = "local_counter", phase = "header_filter",
    action = { redis_incr_key = { key = "failed_login_attempts:%{remote_addr}", expire = 300 } },
}, plugin_conf, "header_filter")
ngx.timer.at = real_timer_at

ok(scheduled == 1, "in header_filter the increment is deferred to a timer")
eq(incr_calls[1] and incr_calls[1].key, "failed_login_attempts:192.0.2.10",
   "header_filter resolves to the SAME key as access (no phase drift)")

utils.redis_incr_key = real_incr

-- ---------------------------------------------------------------------------
-- 4. set_variable with a %{...} value
-- ---------------------------------------------------------------------------
print("\n-- access phase: set_variable stores the value, not the template --")

fresh_access_request()
ok(engine:apply_set_variable({ name = "client_ip", value = "%{remote_addr}", type = "shared" },
                             kong.ctx.plugin, kong.ctx.shared),
   "apply_set_variable returns true for a shared write")
eq(kong.ctx.shared.client_ip, "192.0.2.10",
   "ctx.shared holds the resolved IP, not \"%{remote_addr}\"")

fresh_access_request()
engine:apply_set_variable({ name = "route_key", value = "%{request.method}:%{request.path}", type = "plugin" },
                          kong.ctx.plugin, kong.ctx.shared)
eq(kong.ctx.plugin.route_key, "POST:/login",
   "ctx.plugin holds a fully resolved multi-macro template")

-- driven through the action dispatcher, the way a rule fires it
fresh_access_request()
engine:apply_action_side_effects({
    id = "stash-ip", phase = "access",
    action = { set_variable = { name = "karna_client_ip", value = "%{remote_addr}", type = "shared" } },
}, plugin_conf, "access")
eq(kong.ctx.shared.karna_client_ip, "192.0.2.10",
   "the set_variable action resolves through the real dispatcher in access")

-- non-string values are still written through untouched
fresh_access_request()
engine:apply_set_variable({ name = "skip", value = false, type = "shared" },
                          kong.ctx.plugin, kong.ctx.shared)
eq(kong.ctx.shared.skip, false, "value:false is still a legitimate assignment")

-- ---------------------------------------------------------------------------
-- 5. header_filter: inspection-table variables still resolve
-- ---------------------------------------------------------------------------
print("\n-- header_filter: the inspection table still drives the rich variables --")

H.reset()
H.request.method  = "POST"
H.request.path    = "/login"
H.request.headers = { Host = "app.example" }
kong.ctx.plugin.inspection_table = {
    { ["remote_addr"] = "192.0.2.10" },
    { ["request.header.value:host"] = "app.example" },
    { ["response.status"] = "403" },
}

eq(engine:replace_variable_in_string("h:%{request.header.value:host}"), "h:app.example",
   "an inspection-table variable resolves in header_filter")
eq(engine:replace_variable_in_string("s:%{response.status}"), "s:403",
   "a response-phase variable resolves in header_filter")
eq(engine:replace_variable_in_string("ip:%{remote_addr}"), "ip:192.0.2.10",
   "%{remote_addr} resolves to the same value it did from the table")
eq(engine:replace_variable_in_string("%{remote_addr}/%{request.header.value:host}"),
   "192.0.2.10/app.example",
   "request-context and inspection-table macros mix in one template")

-- ---------------------------------------------------------------------------
-- 6 & 7. fail-soft: unknown macros stay literal, `%` in a value is not fatal
-- ---------------------------------------------------------------------------
print("\n-- fail-soft --")

fresh_access_request()
eq(engine:replace_variable_in_string("k:%{no.such.variable}"), "k:%{no.such.variable}",
   "an unresolvable macro is left literal in access")

H.reset()
kong.ctx.plugin.inspection_table = { { ["request.header.value:host"] = "app.example" } }
eq(engine:replace_variable_in_string("k:%{no.such.variable}"), "k:%{no.such.variable}",
   "an unresolvable macro is left literal in header_filter too")

-- A resolved value carrying a `%` is ordinary input (an encoded byte, a
-- percentage). Handed to gsub as a REPLACEMENT STRING it is an error --
-- "invalid capture index %2" -- which in the access phase is a 500. The
-- substitution goes through a function now, so the value stays literal.
H.reset()
kong.ctx.plugin.inspection_table = { { ["response.status"] = "100%25 %win" } }
local called_ok, out = pcall(engine.replace_variable_in_string, engine, "t:%{response.status}")
ok(called_ok, "a resolved value containing `%` does not throw", out)
eq(out, "t:100%25 %win", "the `%` value is substituted verbatim")

-- A magic pattern character in the VARIABLE NAME (`-` is a lazy quantifier)
-- made the substitution pattern stop matching the text it had been built
-- from, so the macro silently stayed literal even with the value in hand.
H.reset()
kong.ctx.plugin.inspection_table = { { ["request.header.value:x-consumer-id"] = "acme-42" } }
eq(engine:replace_variable_in_string("c:%{request.header.value:x-consumer-id}"), "c:acme-42",
   "a `-` in the variable name does not break the substitution")

-- a non-string argument is returned unchanged rather than crashing
ok(engine:replace_variable_in_string(nil) == nil, "nil in, nil out")
ok(engine:replace_variable_in_string(42) == 42, "a number is returned unchanged")

print(string.format("\n%d test(s) failed", fails))
os.exit(fails == 0 and 0 or 1)
