-- ka-unittest/default_block_response.lua
--
-- Unit-test the default block response builder: the single point of
-- truth for the body + headers Karna serves on its own terminal
-- responses (rule blocks, always-on validation gates, rate-limit 429).
--
-- Precedence under test:
--   body:    explicit (rule/override authored)
--            → conf.default_block_response_body
--            → built-in fallback
--   headers: built-in defaults ← conf.default_block_response_headers
--            ← explicit ← extra (x-karna-rule-id), lowercased keys.
--
-- We replicate `build_block_response` inline (same convention as
-- rule_overrides.lua and fix_matched_parts.lua) so the test stays free
-- of kong/ngx globals. KEEP IN SYNC with
-- kong/plugins/karna/modules/ka_utils.lua.

local fails = 0
local function ok(cond, name)
    if cond then
        print("  ok  - " .. name)
    else
        print("  FAIL- " .. name)
        fails = fails + 1
    end
end

-- ============================================================
-- SUT — copy from ka_utils.lua.
-- ============================================================
local DEFAULT_BLOCK_HEADERS = {
    ["content-type"] = "text/plain",
    ["cache-control"] = "max-age=0, private, no-store, no-cache, must-revalidate",
}

local function build_block_response(plugin_conf, explicit_body, explicit_headers, fallback_body, extra_headers)
    local body = explicit_body
    if body == nil and plugin_conf then
        body = plugin_conf.default_block_response_body
    end
    if body == nil then
        body = fallback_body
    end

    local headers = {}
    for k, v in pairs(DEFAULT_BLOCK_HEADERS) do
        headers[k] = v
    end
    local conf_headers = plugin_conf and plugin_conf.default_block_response_headers
    if type(conf_headers) == "table" then
        for k, v in pairs(conf_headers) do
            if type(k) == "string" and type(v) == "string" then
                headers[k:lower()] = v
            end
        end
    end
    if type(explicit_headers) == "table" then
        for k, v in pairs(explicit_headers) do
            if type(k) == "string" then
                headers[k:lower()] = v
            end
        end
    end
    if extra_headers then
        for k, v in pairs(extra_headers) do
            headers[k] = v
        end
    end

    return body, headers
end

-- ============================================================
-- body precedence
-- ============================================================
print("- body: nothing configured → built-in fallback")
local body = build_block_response({}, nil, nil, "Forbidden")
ok(body == "Forbidden", "fallback body served")

print("- body: conf default beats fallback")
local conf = { default_block_response_body = "<html><body>Blocked.</body></html>" }
body = build_block_response(conf, nil, nil, "Forbidden")
ok(body == "<html><body>Blocked.</body></html>", "conf default body served")

print("- body: explicit (rule-authored) beats conf default")
body = build_block_response(conf, "Custom rule body", nil, "Forbidden")
ok(body == "Custom rule body", "explicit body wins")

print("- body: nil plugin_conf doesn't crash (gate called before conf ready)")
body = build_block_response(nil, nil, nil, "Forbidden")
ok(body == "Forbidden", "fallback body with nil conf")

-- ============================================================
-- headers merge chain
-- ============================================================
print("- headers: nothing configured → built-in defaults")
local _, headers = build_block_response({}, nil, nil, "x")
ok(headers["content-type"] == "text/plain", "built-in content-type")
ok(headers["cache-control"] ~= nil, "built-in cache-control")

print("- headers: conf defaults merge over built-ins, operator key wins")
conf = { default_block_response_headers = { ["Content-Type"] = "text/html", ["x-blocked-by"] = "karna" } }
_, headers = build_block_response(conf, nil, nil, "x")
ok(headers["content-type"] == "text/html", "operator content-type wins (lowercased, no dup)")
ok(headers["Content-Type"] == nil, "no case-duplicate key")
ok(headers["x-blocked-by"] == "karna", "extra operator header added")
ok(headers["cache-control"] ~= nil, "built-in cache-control preserved")

print("- headers: explicit (rule-authored) beat conf defaults")
_, headers = build_block_response(conf, nil, { ["content-type"] = "application/json" }, "x")
ok(headers["content-type"] == "application/json", "rule header wins over conf default")
ok(headers["x-blocked-by"] == "karna", "conf header still merged")

print("- headers: extra (x-karna-rule-id) applied last")
_, headers = build_block_response(conf, nil, nil, "x", { ["x-karna-rule-id"] = "941100" })
ok(headers["x-karna-rule-id"] == "941100", "extra header present")

print("- headers: non-string conf values ignored (schema guards, belt+braces)")
conf = { default_block_response_headers = { good = "yes", bad = 42, [1] = "nope" } }
_, headers = build_block_response(conf, nil, nil, "x")
ok(headers["good"] == "yes", "string value kept")
ok(headers["bad"] == nil, "non-string value dropped")
ok(headers[1] == nil, "non-string key dropped")

print("- headers: fresh table every call (no cached-rule mutation)")
local rule_headers = { ["content-type"] = "text/plain" }
_, headers = build_block_response({}, nil, rule_headers, "x", { ["x-karna-rule-id"] = "1" })
ok(rule_headers["x-karna-rule-id"] == nil, "input table untouched")
ok(headers ~= rule_headers, "returned table is a copy")

-- ============================================================
-- end-to-end shapes: the three serve paths
-- ============================================================
print("- gate shape: default page + gate id header")
conf = {
    default_block_response_body = "<html>Blocked</html>",
    default_block_response_headers = { ["content-type"] = "text/html" },
}
body, headers = build_block_response(conf, nil, nil, "Method Not Allowed", { ["x-karna-rule-id"] = "method_allowed" })
ok(body == "<html>Blocked</html>", "gate serves the operator page")
ok(headers["content-type"] == "text/html", "gate serves the operator content-type")
ok(headers["x-karna-rule-id"] == "method_allowed", "gate id survives the merge")

print("- rule shape: CRS rule (no baked body) falls to operator page")
body = build_block_response(conf, nil, nil, "Forbidden\r\n")
ok(body == "<html>Blocked</html>", "CRS block serves the operator page")

print("- rule shape: authored fixed_response body still wins")
body = build_block_response(conf, "Go away.", nil, "Forbidden\r\n")
ok(body == "Go away.", "authored body wins over operator page")

print("- rate-limit shape: default page on 429, Retry-After added by caller")
body, headers = build_block_response(conf, nil, nil, "Too Many Requests\r\n")
if not headers["retry-after"] then
    headers["Retry-After"] = "60"
end
ok(body == "<html>Blocked</html>", "429 serves the operator page")
ok(headers["Retry-After"] == "60", "Retry-After added when absent")

print("- rate-limit shape: authored retry-after not double-set")
body, headers = build_block_response(conf, nil, { ["Retry-After"] = "120" }, "Too Many Requests\r\n")
if not headers["retry-after"] then
    headers["Retry-After"] = "60"
end
ok(headers["retry-after"] == "120", "authored value kept (lowercased)")
ok(headers["Retry-After"] == nil, "no duplicate mixed-case key")

print(string.format("\n%d test(s) failed", fails))
os.exit(fails == 0 and 0 or 1)
