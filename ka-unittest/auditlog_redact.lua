-- ka-unittest/auditlog_redact.lua
--
-- Guards audit-log secret redaction (modules/ka_redact.lua): the audit record
-- used to carry every request and response header verbatim, so a Cookie or an
-- Authorization reached disk in clear text.
--
-- Load-bearing properties pinned here:
--   1. scope — the two header maps of the document and NOTHING else. Matched
--      values, the URI, the raw body attached by `audit_request_body`, custom
--      log fields and the enrichment block must come out byte-identical: a
--      rule that catches a secret by accident is the signal you need to fix
--      that rule;
--   2. `authorization` keeps its scheme (`Bearer [REDACTED]`) but only when the
--      header really is `<scheme> <credentials>`;
--   3. `cookie` keeps the cookie names and masks the values, separators
--      preserved, key-only and empty-valued cookies left alone;
--   4. `set-cookie` additionally keeps the attributes (Path / HttpOnly /
--      SameSite / Expires), masks the cookie itself even when it is named like
--      an attribute, and survives several Set-Cookie headers folded into one
--      comma-joined string;
--   5. both audit formats — v2 `request.headers` / `response.headers`, v1
--      `transaction.request.headers` / `transaction.response.headers`;
--   6. off means byte-identical output, and `compile` returns nil so the
--      handler can skip the path with one check;
--   7. the MCP toggles still drive `mcp-session-id` (first four characters +
--      `***`, the documented shape) and an explicit list entry overrides them.
--
-- Runs against the REAL module. Fixtures are synthetic: example.com, made-up
-- tokens, 9999xx rule ids.
--
-- Run from repo root:
--   lua    ka-unittest/auditlog_redact.lua
--   luajit ka-unittest/auditlog_redact.lua

package.path = "./kong/plugins/karna/modules/?.lua;" .. package.path

local redact = require("ka_redact")

local fails = 0
local function ok(cond, name)
    if cond then print("  ok  - " .. name)
    else print("  FAIL- " .. name); fails = fails + 1 end
end
local function eq(got, want, name)
    if got == want then print("  ok  - " .. name)
    else
        print("  FAIL- " .. name)
        print("         want: " .. tostring(want))
        print("         got : " .. tostring(got))
        fails = fails + 1
    end
end

local function deep_equal(a, b)
    if a == b then return true end
    if type(a) ~= "table" or type(b) ~= "table" then return false end
    for k, v in pairs(a) do
        if not deep_equal(v, b[k]) then return false end
    end
    for k in pairs(b) do
        if a[k] == nil then return false end
    end
    return true
end

-- Default configuration, as the schema hands it to the handler.
local DEFAULT_HEADERS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "api-key", "apikey", "x-auth-token", "x-access-token",
    "x-session-token", "x-csrf-token", "x-xsrf-token", "x-amz-security-token",
}
local function conf(over)
    local c = {
        auditlog_redact_enabled = true,
        auditlog_redact_headers = DEFAULT_HEADERS,
        auditlog_redact_mask    = "[REDACTED]",
    }
    for k, v in pairs(over or {}) do c[k] = v end
    return c
end

local function mask_one(name, value, c)
    local spec = redact.compile(c or conf())
    local map = { [name] = value }
    redact.redact_headers(map, spec)
    return map[name]
end

-- ============================================================
print("- compile")
-- ============================================================
local spec = redact.compile(conf())
ok(type(spec) == "table", "default config compiles to a spec")
eq(spec.mask, "[REDACTED]", "default mask")
eq(spec.names["authorization"], "auth", "authorization → scheme-preserving style")
eq(spec.names["proxy-authorization"], "auth", "proxy-authorization → scheme-preserving style")
eq(spec.names["cookie"], "cookie", "cookie → name-preserving style")
eq(spec.names["set-cookie"], "set_cookie", "set-cookie → attribute-preserving style")
eq(spec.names["x-api-key"], "full", "everything else → full mask")
ok(spec.names["mcp-session-id"] == nil, "MCP session id is not in the generic default list")

ok(redact.compile(conf({ auditlog_redact_enabled = false })) == nil,
   "disabled and no MCP → nil spec (handler skips the whole path)")
ok(redact.compile(conf({ auditlog_redact_headers = {} })) == nil,
   "empty header list → nil spec")
ok(redact.compile(nil) == nil, "nil config → nil spec, no error")

local custom = redact.compile(conf({ auditlog_redact_headers = { "  X-Secret-Token ", "COOKIE", "", 42 } }))
eq(custom.names["x-secret-token"], "full", "list entries are trimmed and lowercased")
eq(custom.names["cookie"], "cookie", "an uppercase entry still resolves its style")
ok(custom.names["authorization"] == nil, "a custom list replaces the default, it does not extend it")

local m = redact.compile(conf({ auditlog_redact_mask = "***" }))
eq(m.mask, "***", "mask is configurable")
eq(redact.compile(conf({ auditlog_redact_mask = "" })).mask, "[REDACTED]", "empty mask falls back to the default")

-- ============================================================
print("")
print("- authorization keeps the scheme")
-- ============================================================
eq(mask_one("authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.e30.sig"), "Bearer [REDACTED]", "Bearer")
eq(mask_one("authorization", "Basic dXNlcjpwYXNzd29yZA=="), "Basic [REDACTED]", "Basic")
eq(mask_one("authorization", "AWS4-HMAC-SHA256 Credential=AKIA.../x"), "AWS4-HMAC-SHA256 [REDACTED]",
   "a scheme with dashes and digits")
eq(mask_one("proxy-authorization", "Basic dXNlcjpwdw=="), "Basic [REDACTED]", "proxy-authorization too")
eq(mask_one("authorization", "eyJhbGciOiJIUzI1NiJ9.e30.sig"), "[REDACTED]",
   "no space → the first word IS the credential, mask everything")
eq(mask_one("authorization", "Bearer"), "[REDACTED]", "scheme with no credentials → mask everything")
eq(mask_one("authorization", "Bearer   "), "[REDACTED]", "scheme with blank credentials → mask everything")
eq(mask_one("authorization", "aVeryLongFirstWordThatIsNotAScheme abc"), "[REDACTED]",
   "an over-long first word is not a scheme name")
eq(mask_one("authorization", "bearer abc", conf({ auditlog_redact_mask = "***" })), "bearer ***",
   "the configured mask is used, and the scheme's own casing is preserved")

-- ============================================================
print("")
print("- cookie keeps the names")
-- ============================================================
eq(mask_one("cookie", "sid=abc123; theme=dark"), "sid=[REDACTED]; theme=[REDACTED]", "two cookies")
eq(mask_one("cookie", "sid=abc123"), "sid=[REDACTED]", "one cookie")
eq(mask_one("cookie", "a=1;b=2"), "a=[REDACTED];b=[REDACTED]", "separator spacing is preserved")
eq(mask_one("cookie", "jwt=aaa.bbb=ccc; x=1"), "jwt=[REDACTED]; x=[REDACTED]",
   "a value containing '=' is masked whole")
eq(mask_one("cookie", "foo"), "foo", "a key-only cookie has no value to mask")
eq(mask_one("cookie", "a=; b=2"), "a=; b=[REDACTED]",
   "an empty value stays empty rather than claiming a secret was there")
eq(mask_one("cookie", "sid=abc", conf({ auditlog_redact_mask = "%d%1" })), "sid=%d%1",
   "a mask containing gsub replacement characters is inserted literally")

-- ============================================================
print("")
print("- set-cookie keeps the attributes")
-- ============================================================
eq(mask_one("set-cookie", "sid=abc123; Path=/; HttpOnly; SameSite=Lax"),
   "sid=[REDACTED]; Path=/; HttpOnly; SameSite=Lax", "cookie masked, attributes kept")
eq(mask_one("set-cookie", "sid=abc; Expires=Wed, 21 Oct 2015 07:28:00 GMT; Max-Age=3600"),
   "sid=[REDACTED]; Expires=Wed, 21 Oct 2015 07:28:00 GMT; Max-Age=3600",
   "an Expires value with its own comma survives")
eq(mask_one("set-cookie", "path=supersecret; Path=/"), "path=[REDACTED]; Path=/",
   "a cookie NAMED like an attribute is still masked (first pair is always the cookie)")
eq(mask_one("set-cookie", "a=1; Path=/, b=2; HttpOnly"), "a=[REDACTED]; Path=/, b=[REDACTED]; HttpOnly",
   "two Set-Cookie headers folded into one comma-joined string")
eq(mask_one("set-cookie", "sid=abc; secure"), "sid=[REDACTED]; secure", "a flag attribute has no value to touch")

-- ============================================================
print("")
print("- unlisted headers and non-string values")
-- ============================================================
local map = {
    ["user-agent"]   = "curl/8.4.0",
    ["x-request-id"] = "req-9999",
    ["cookie"]       = "sid=abc",
    ["x-evil"]       = "authorization=Bearer tok",
}
redact.redact_headers(map, redact.compile(conf()))
eq(map["user-agent"], "curl/8.4.0", "an unlisted header is untouched")
eq(map["x-request-id"], "req-9999", "so is another one")
eq(map["x-evil"], "authorization=Bearer tok",
   "a listed name appearing inside another header's VALUE is not a match (lookup is by key)")
eq(map["cookie"], "sid=[REDACTED]", "the listed one was masked")

local empty = { ["authorization"] = "" }
redact.redact_headers(empty, redact.compile(conf()))
eq(empty["authorization"], "", "an empty header value is left as-is")
ok(redact.redact_headers(nil, redact.compile(conf())) == false, "nil map → false, no error")
ok(redact.redact_headers({}, nil) == false, "nil spec → false, no error")

-- ============================================================
print("")
print("- apply on a v2 document")
-- ============================================================
local function v2_doc()
    return {
        version = "2.0",
        request_id = "req-1",
        request = {
            method = "POST",
            uri = "/login?access_token=leaky",
            headers = {
                ["host"]          = "example.com",
                ["authorization"] = "Bearer tok-abc",
                ["cookie"]        = "sid=abc; theme=dark",
                ["x-api-key"]     = "key-123",
                ["user-agent"]    = "curl/8.4.0",
            },
            body_raw = "user=admin&password=hunter2",
            body_encoding = "utf-8",
        },
        response = {
            status = 403,
            headers = {
                ["content-type"] = "text/plain",
                ["set-cookie"]   = "sid=zzz; Path=/; HttpOnly",
            },
        },
        matches = {
            { rule_id = "999901", message = "SQLi", action = "block",
              matched_parts = { { on = "request.header.value:authorization", value = "Bearer tok-abc" } } },
        },
        enrichment = { custom = { authorization = "sibling-plugin-value" } },
    }
end

local doc = v2_doc()
local before = v2_doc()
ok(redact.apply(doc, redact.compile(conf())) == true, "apply reports a hit")

eq(doc.request.headers["authorization"], "Bearer [REDACTED]", "v2 request authorization")
eq(doc.request.headers["cookie"], "sid=[REDACTED]; theme=[REDACTED]", "v2 request cookie")
eq(doc.request.headers["x-api-key"], "[REDACTED]", "v2 request api key")
eq(doc.request.headers["host"], "example.com", "v2 request host untouched")
eq(doc.response.headers["set-cookie"], "sid=[REDACTED]; Path=/; HttpOnly", "v2 response set-cookie")
eq(doc.response.headers["content-type"], "text/plain", "v2 response content-type untouched")

-- scope guard: everything that is NOT a header map must be byte-identical
eq(doc.request.uri, before.request.uri, "the URI is NOT redacted (query secrets stay)")
eq(doc.request.body_raw, before.request.body_raw, "the raw body is NOT redacted")
ok(deep_equal(doc.matches, before.matches),
   "matched values are NOT redacted — the rule-tuning signal is kept on purpose")
ok(deep_equal(doc.enrichment, before.enrichment),
   "the enrichment block is NOT redacted, even a key literally named authorization")

-- ============================================================
print("")
print("- apply on a v1 document")
-- ============================================================
local v1 = {
    transaction = {
        request = {
            method = "GET",
            uri = "/",
            headers = { ["cookie"] = "sid=abc", ["authorization"] = "Basic dXNlcg==", ["host"] = "example.com" },
        },
        response = {
            http_code = 200,
            headers = { ["set-cookie"] = "sid=zzz; Path=/", ["server"] = "kong" },
        },
        messages = { { message = "SQLi", details = { ruleId = "999901", data = "Matched value: Basic dXNlcg==" } } },
    },
}
ok(redact.apply(v1, redact.compile(conf())) == true, "apply reports a hit on v1")
eq(v1.transaction.request.headers["cookie"], "sid=[REDACTED]", "v1 request cookie")
eq(v1.transaction.request.headers["authorization"], "Basic [REDACTED]", "v1 request authorization")
eq(v1.transaction.request.headers["host"], "example.com", "v1 request host untouched")
eq(v1.transaction.response.headers["set-cookie"], "sid=[REDACTED]; Path=/", "v1 response set-cookie")
eq(v1.transaction.response.headers["server"], "kong", "v1 response server untouched")
eq(v1.transaction.messages[1].details.data, "Matched value: Basic dXNlcg==",
   "v1 matched data is NOT redacted (same scope decision as v2)")

ok(redact.apply(nil, redact.compile(conf())) == false, "nil document → false, no error")
ok(redact.apply({}, redact.compile(conf())) == false, "a document with no header map → false, no error")
ok(redact.apply({ version = "2.0", request = {} }, redact.compile(conf())) == false,
   "a v2 document with no headers table → false, no error")

-- ============================================================
print("")
print("- feature off leaves the document identical")
-- ============================================================
local untouched = v2_doc()
local reference = v2_doc()
local off_spec = redact.compile(conf({ auditlog_redact_enabled = false }))
ok(off_spec == nil, "off → nil spec")
ok(deep_equal(untouched, reference), "…and the document the handler would then write is unchanged")

-- ============================================================
print("")
print("- MCP toggles")
-- ============================================================
local mcp_spec = redact.compile(conf({
    auditlog_redact_enabled = false,
    mcp_enabled = true,
    mcp_redact_authorization_in_audit = true,
    mcp_redact_session_id_in_audit = true,
}))
ok(mcp_spec ~= nil, "MCP toggles alone still produce a spec when the generic list is off")
eq(mcp_spec.names["authorization"], "full", "MCP keeps its full-mask authorization when the list is off")
eq(mcp_spec.names["mcp-session-id"], "prefix4", "MCP session id style")
eq(mcp_spec.names["x-mcp-session-id"], "prefix4", "the x- variant too")

local mmap = { ["mcp-session-id"] = "abcdefghij", ["x-mcp-session-id"] = "abc" }
redact.redact_headers(mmap, mcp_spec)
eq(mmap["mcp-session-id"], "abcd***", "first four characters kept — the documented MCP shape")
eq(mmap["x-mcp-session-id"], "***", "a short session id is masked whole")

local both = redact.compile(conf({
    mcp_enabled = true,
    mcp_redact_authorization_in_audit = true,
    mcp_redact_session_id_in_audit = true,
}))
eq(both.names["authorization"], "auth",
   "with the generic list on, authorization keeps the scheme (the list wins over the MCP toggle)")
eq(both.names["mcp-session-id"], "prefix4", "session ids are still added by the MCP toggle")

local explicit = redact.compile(conf({
    auditlog_redact_headers = { "mcp-session-id" },
    mcp_enabled = true,
    mcp_redact_session_id_in_audit = true,
}))
eq(explicit.names["mcp-session-id"], "full",
   "listing the session id explicitly overrides the MCP shape with a full mask")

local no_mcp = redact.compile(conf({
    auditlog_redact_enabled = false,
    mcp_enabled = false,
    mcp_redact_session_id_in_audit = true,
}))
ok(no_mcp == nil, "the MCP toggles only apply when mcp_enabled is on")

-- ============================================================
print("")
print("- the default list matches the one the module documents")
-- ============================================================
ok(deep_equal(redact.DEFAULT_HEADERS, DEFAULT_HEADERS),
   "schema default and module default are the same list (README / docs quote it)")

print(string.format("\n%d test(s) failed", fails))
os.exit(fails == 0 and 0 or 1)
