-- ka-unittest/response_status_variable.lua
--
-- `response.status` must be the status the CLIENT receives, not the upstream's.
--
-- The two are the same for a proxied request and differ exactly when a plugin
-- generated the response. Karna read `kong.service.response.get_status()`, the
-- upstream one, so a response Karna itself produced — the `rate_limit` 429, a
-- `fixed_response` block — had no upstream status behind it and
-- `response.status` resolved to nothing. A header_filter rule keyed on it could
-- never match, silently: the phase runs and the rule is evaluated, only the
-- variable reports the wrong thing. That is the "count my own 429s" shape, and
-- it produced no Redis write and no error.
--
-- The audit log has always reported the client-facing status (ka_utils uses
-- kong.response.get_status for both the v1 `http_code` and the v2 `status`), so
-- before this the record said 429 while no rule could see 429.
--
-- Driven through the REAL get_inspection_table, which is the only producer of
-- the `response.*` keys the condition matcher reads back.
--
-- Fixtures are synthetic.
--
-- Run from repo root:
--   lua    ka-unittest/response_status_variable.lua
--   luajit ka-unittest/response_status_variable.lua

-- The harness does the module wiring (real engine, stubbed resty/ffi/cjson) and
-- installs a kong/ngx pair. We then swap the three functions this test is about
-- and RELOAD the engine, because ka_engine captures them into locals at module
-- load: overriding them afterwards would change nothing.
local H = dofile("./ka-unittest/_engine_harness.lua")

local fails = 0
local function ok(cond, name, detail)
    if cond then print("  ok  - " .. name)
    else print("  FAIL- " .. name .. (detail and ("  (" .. tostring(detail) .. ")") or "")); fails = fails + 1 end
end
local function eq(got, want, name)
    ok(got == want, name, "got " .. tostring(got) .. ", want " .. tostring(want))
end

-- The two statuses are deliberately different so the test can only pass by
-- reading the right one. `__UPSTREAM = nil` models "no upstream response",
-- which is what a plugin-generated response actually looks like.
_G.__PHASE    = "header_filter"
_G.__CLIENT   = 429
_G.__UPSTREAM = nil

ngx.get_phase                    = function() return _G.__PHASE end
kong.response.get_status         = function() return _G.__CLIENT end
kong.service.response.get_status = function() return _G.__UPSTREAM end

-- KARNA_UNIT_ENGINE=<path> loads that file as the engine instead of the
-- working tree's, same convention as _engine_harness.lua. Point it at the
-- pre-fix ka_engine.lua and the "client-facing status wins" assertions fail,
-- which is the A/B that says this test guards something real.
local engine = dofile(os.getenv("KARNA_UNIT_ENGINE")
                      or "./kong/plugins/karna/modules/ka_engine.lua")

-- Read one key back out of the inspection table the way the `^response%.`
-- branch of the condition matcher does.
local function inspect_value(key)
    for _, row in ipairs(kong.ctx.plugin.inspection_table or {}) do
        for k, v in pairs(row) do
            if k == key then return v end
        end
    end
    return nil
end

local function build(client, upstream)
    _G.__CLIENT, _G.__UPSTREAM = client, upstream
    H.reset()
    engine:get_inspection_table({})
    return inspect_value("response.status")
end

-- ---------------------------------------------------------------------------
print("\n-- a response Karna generated itself --")
-- ---------------------------------------------------------------------------
-- rate_limit answered 429 in the access phase, so there is no upstream response.
eq(build(429, nil), "429",
   "the rate_limit 429 is visible to a header_filter rule")

-- A fixed_response block, same shape.
eq(build(403, nil), "403", "a fixed_response block is visible too")

-- ---------------------------------------------------------------------------
print("\n-- a proxied response --")
-- ---------------------------------------------------------------------------
-- The ordinary case: the two agree, and nothing about it changes.
eq(build(200, 200), "200", "an upstream 200 still reads 200")
eq(build(502, 502), "502", "an upstream 502 still reads 502")
eq(build(429, 429), "429", "an upstream that rate-limits on its own still reads 429")

-- ---------------------------------------------------------------------------
print("\n-- the client-facing status is the one that wins --")
-- ---------------------------------------------------------------------------
-- The regression guard. If the binding goes back to kong.service.response,
-- this is the assertion that fails: it is the only case where the two differ
-- AND both exist, so reading either one yields a value and only one is right.
eq(build(403, 200), "403",
   "upstream 200 rewritten to 403 downstream → the rule sees 403, not 200")

-- ---------------------------------------------------------------------------
print("\n-- the key is only produced in the response phase --")
-- ---------------------------------------------------------------------------
_G.__PHASE = "access"
H.reset()
-- handler.lua initialises this in access before the engine runs; the harness
-- reset does not, so stand it in rather than exercise a shape Kong never has.
kong.ctx.plugin.rule_variables = {}
_G.__CLIENT, _G.__UPSTREAM = 429, nil
engine:get_inspection_table({})
eq(inspect_value("response.status"), nil,
   "an access-phase rule still resolves no response.status (the response does not exist yet)")
_G.__PHASE = "header_filter"

print(string.format("\n%d test(s) failed", fails))
os.exit(fails == 0 and 0 or 1)
