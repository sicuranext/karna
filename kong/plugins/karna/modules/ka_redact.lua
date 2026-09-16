--- ka_redact.lua — audit-log secret redaction.
---
--- Karna's audit record carries every request and response header verbatim,
--- which means a `Cookie`, an `Authorization` or an API key lands on disk in
--- clear text and is then shipped wherever the log collector ships it. This
--- module masks the values of a configurable set of header names before the
--- record is handed to the async writer.
---
--- Scope, deliberately narrow: the two header maps of the audit document and
--- nothing else. Matched values (`matches[].matched_parts[]` in v2,
--- `transaction.messages[].details.data` in v1) are NOT touched — a rule that
--- catches a secret by accident is exactly the signal you need to fix that
--- rule, and losing it would cost more than it protects. The URI, the request
--- body attached by `audit_request_body`, custom log fields and the enrichment
--- block are likewise left alone.
---
--- Cost: the whole thing runs in the log phase, after the response has left
--- the client, and only on requests that are actually written (with
--- `auditlog_only_on_match` most are not). The per-record work is one hash
--- lookup per configured name against each of the two maps — the loop is over
--- the spec (bounded by the operator's config), never over the header map
--- (bounded by whatever the client chose to send). The spec itself is compiled
--- once per (plugin instance, configuration) and cached by the caller.
---
--- Header-map keys are lowercase: both `kong.request.get_headers()` and
--- `kong.service.response.get_headers()` normalise them, and the audit
--- builders copy those keys through unchanged. The direct indexing below
--- depends on that invariant; ka-unittest/auditlog_redact.lua pins it.

local _M = {}

local string_lower  = string.lower
local string_gsub   = string.gsub
local string_match  = string.match
local type          = type
local ipairs        = ipairs
local pairs         = pairs

local DEFAULT_MASK = "[REDACTED]"

-- Header names masked unless the operator narrows the list. Credentials,
-- session material and API keys: values with no forensic use that a log
-- pipeline has no business storing.
--
-- The MCP session-id headers are NOT here. They belong to
-- `mcp_redact_session_id_in_audit`, which masks them in its own documented
-- shape (first four characters + `***`); listing one of them explicitly in
-- `auditlog_redact_headers` overrides that with a full mask.
local DEFAULT_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "apikey",
    "x-auth-token",
    "x-access-token",
    "x-session-token",
    "x-csrf-token",
    "x-xsrf-token",
    "x-amz-security-token",
}

-- Set-Cookie attributes, i.e. the `name=value` pairs of that header that are
-- not the cookie itself. They describe the cookie's scope and flags — Secure,
-- HttpOnly, SameSite are the three things you most want to see in a log when
-- investigating a session problem — so they survive the mask.
local SET_COOKIE_ATTRS = {
    ["path"]        = true,
    ["domain"]      = true,
    ["expires"]     = true,
    ["max-age"]     = true,
    ["samesite"]    = true,
    ["secure"]      = true,
    ["httponly"]    = true,
    ["version"]     = true,
    ["comment"]     = true,
    ["partitioned"] = true,
    ["priority"]    = true,
}

-- Masking style per header name. Everything not named here is replaced whole.
local function style_for(name)
    if name == "cookie" then
        return "cookie"
    elseif name == "set-cookie" then
        return "set_cookie"
    elseif name == "authorization" or name == "proxy-authorization" then
        return "auth"
    end
    return "full"
end

-- `Bearer eyJhbGciOi...` → `Bearer [REDACTED]`.
--
-- The scheme is not a secret and it is the first thing you look at when an
-- endpoint starts answering 401: Basic, Bearer, Negotiate and AWS4-HMAC-SHA256
-- are different problems. It survives only when the header really is
-- `<scheme> <credentials>`: a bare token with no space is masked whole,
-- because then the "scheme" would be the credential itself. The length cap is
-- the same guard from the other side — a 30-character first word is not a
-- scheme name.
local function mask_authorization(value, mask)
    local scheme = string_match(value, "^%s*([A-Za-z][A-Za-z0-9%-%.%+_]*)%s+%S")
    if scheme and #scheme <= 20 then
        return scheme .. " " .. mask
    end
    return mask
end

-- `sid=abc; theme=dark` → `sid=[REDACTED]; theme=[REDACTED]`.
--
-- Which cookies the client sent is the useful half of the header (it tells you
-- whether the request was authenticated, whether the consent cookie was set,
-- whether a tracker is leaking into your API); the values are the half that
-- must not be stored. Separators are preserved byte for byte, and a key-only
-- cookie (`Cookie: foo`) has no value to mask, so it passes through. An empty
-- value stays empty rather than becoming a mask that claims a secret was
-- there: the pattern requires at least one character after the `=`.
local function mask_cookie(value, mask)
    -- gsub expands `%` in a replacement string; a mask is operator-supplied.
    local escaped = string_gsub(mask, "%%", "%%%%")
    return (string_gsub(value, "=[^;]+", "=" .. escaped))
end

-- `sid=abc; Path=/; HttpOnly` → `sid=[REDACTED]; Path=/; HttpOnly`.
--
-- The first `name=value` pair is the cookie and is always masked, even when it
-- is named like an attribute (`Set-Cookie: path=secret` is a cookie called
-- `path`, not a Path attribute). Later pairs are kept when they name a known
-- attribute and masked otherwise — which is also what makes several Set-Cookie
-- headers folded into one comma-joined string come out right: the second
-- cookie is a later pair with a name that is not an attribute.
local function mask_set_cookie(value, mask)
    local n = 0
    -- A value returned from a gsub function is inserted literally, so the mask
    -- needs no escaping on this path.
    return (string_gsub(value, "([^;,=]+)=([^;,]+)", function(name, val)
        n = n + 1
        if n > 1 and SET_COOKIE_ATTRS[string_lower((string_gsub(name, "^%s+", "")))] then
            return name .. "=" .. val
        end
        return name .. "=" .. mask
    end))
end

-- MCP session id: first four characters kept, the rest replaced by `***`.
-- Enough to correlate two records from the same session without handing the
-- reader a usable session id. This is the shape mcp_redact_session_id_in_audit
-- has always emitted; it ignores `auditlog_redact_mask` on purpose, so an
-- existing MCP consumer sees no change.
local function mask_prefix4(value)
    if #value > 4 then
        return value:sub(1, 4) .. "***"
    end
    return "***"
end

local function mask_value(value, style, mask)
    if style == "cookie" then
        return mask_cookie(value, mask)
    elseif style == "set_cookie" then
        return mask_set_cookie(value, mask)
    elseif style == "auth" then
        return mask_authorization(value, mask)
    elseif style == "prefix4" then
        return mask_prefix4(value)
    end
    return mask
end

--- Compile the redaction spec for a plugin configuration.
--- Returns nil when nothing would ever be masked, so the caller can skip the
--- whole path with a single nil check.
---
--- An empty `auditlog_redact_headers` is a valid way to disable the generic
--- list while keeping the MCP toggles, same as `auditlog_redact_enabled=false`.
function _M.compile(plugin_conf)
    if type(plugin_conf) ~= "table" then return nil end

    local mask = plugin_conf.auditlog_redact_mask
    if type(mask) ~= "string" or mask == "" then
        mask = DEFAULT_MASK
    end

    local names

    if plugin_conf.auditlog_redact_enabled ~= false then
        local list = plugin_conf.auditlog_redact_headers
        if type(list) ~= "table" then
            list = DEFAULT_HEADERS
        end
        for _, raw in ipairs(list) do
            if type(raw) == "string" then
                local name = string_lower((string_gsub(raw, "^%s*(.-)%s*$", "%1")))
                if name ~= "" then
                    names = names or {}
                    names[name] = style_for(name)
                end
            end
        end
    end

    -- MCP-specific names. They only ADD to the set: a name the operator listed
    -- explicitly keeps the style the generic list gave it.
    if plugin_conf.mcp_enabled then
        if plugin_conf.mcp_redact_authorization_in_audit and not (names and names["authorization"]) then
            names = names or {}
            names["authorization"] = "full"
        end
        if plugin_conf.mcp_redact_session_id_in_audit then
            names = names or {}
            if not names["mcp-session-id"]   then names["mcp-session-id"]   = "prefix4" end
            if not names["x-mcp-session-id"] then names["x-mcp-session-id"] = "prefix4" end
        end
    end

    if not names then return nil end
    return { names = names, mask = mask }
end

--- Mask the configured names in one flat header map, in place.
--- Returns true when at least one value was replaced.
function _M.redact_headers(map, spec)
    if type(map) ~= "table" or type(spec) ~= "table" then return false end
    local names = spec.names
    if type(names) ~= "table" then return false end

    local mask = spec.mask or DEFAULT_MASK
    local hit = false
    for name, style in pairs(names) do
        local value = map[name]
        if type(value) == "string" and value ~= "" then
            map[name] = mask_value(value, style, mask)
            hit = true
        end
    end
    return hit
end

--- Apply the spec to a built audit document, in place. Handles both formats:
--- v2 `request.headers` / `response.headers`, v1
--- `transaction.request.headers` / `transaction.response.headers`.
--- Returns true when at least one value was replaced.
function _M.apply(json_log, spec)
    if type(json_log) ~= "table" or type(spec) ~= "table" then return false end

    local request_headers, response_headers

    if json_log.version == "2.0" then
        if type(json_log.request)  == "table" then request_headers  = json_log.request.headers  end
        if type(json_log.response) == "table" then response_headers = json_log.response.headers end
    else
        local transaction = json_log.transaction
        if type(transaction) == "table" then
            if type(transaction.request)  == "table" then request_headers  = transaction.request.headers  end
            if type(transaction.response) == "table" then response_headers = transaction.response.headers end
        end
    end

    local hit = _M.redact_headers(request_headers, spec)
    if _M.redact_headers(response_headers, spec) then hit = true end
    return hit
end

-- Exposed for the unit test: the default list is documented in the README and
-- in docs/configuration.html, and the two must not drift.
_M.DEFAULT_HEADERS = DEFAULT_HEADERS
_M.DEFAULT_MASK    = DEFAULT_MASK

return _M
