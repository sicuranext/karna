-- ka-unittest/fix_matched_parts.lua
--
-- Unit-test the `fix_matched_parts` action — Karna's FP-mitigation
-- primitive that strips dangerous characters from matched targets in
-- place and lets the request flow upstream, instead of issuing a 403.
--
-- This is THE killer feature for false-positive reduction: a payload
-- like `O'Brien` or `Via dell'Orso, 5` that fires an SQLi/XSS rule
-- doesn't block the user — it goes through with the unsafe characters
-- removed.
--
-- We replicate the function inline (instead of loading the full
-- ka_engine module) so the test runs free of ngx/kong globals and
-- inside the plain CI Lua sandbox. KEEP IN SYNC with
-- kong/plugins/karna/modules/ka_engine.lua → _M.__fix_matching_parts.
--
-- Run from repo root:
--   lua ka-unittest/fix_matched_parts.lua

local string_gsub = string.gsub
local string_match = string.match

-- ============================================================
-- kong / ngx mocks — record every mutation the SUT performs so
-- the assertions can read back what would have been sent upstream.
-- ============================================================
local recorded = {}

local function reset_mocks()
    recorded = {
        path = nil,
        query = nil,
        headers = {},
        body = nil,
        body_form = nil,        -- set_body(args, "...urlencoded") capture
        raw_path_returns = nil,
        query_returns = nil,
        header_returns = {},
        body_returns = nil,
        body_form_returns = nil, -- get_body("...urlencoded") seed
    }
end

-- Stand-in for the kong globals the SUT calls. Each setter writes
-- into `recorded.*`; each getter returns whatever the test seeded.
local kong = {
    request = {
        get_raw_path = function() return recorded.raw_path_returns end,
        get_query = function() return recorded.query_returns end,
        get_body = function(_mime) return recorded.body_form_returns end,
    },
    service = {
        request = {
            set_path = function(p) recorded.path = p end,
            set_query = function(q) recorded.query = q end,
            set_header = function(name, v) recorded.headers[name] = v end,
            set_raw_body = function(b) recorded.body = b end,
            set_body = function(args, _mime) recorded.body_form = args end,
        },
    },
}

local function request_get_header(name)
    return recorded.header_returns[name]
end

local function request_get_raw_body()
    return recorded.body_returns
end

-- ============================================================
-- SUT — copy from ka_engine.__fix_matching_parts. Trimmed of the
-- body-in-file branch (that path needs io.open against an actual
-- temp file; the in-memory body branch is the one operators hit
-- 99% of the time and is what we exercise here).
-- ============================================================
local function fix_matching_parts(rule, matched_parts)
    local ue_body
    local ue_dirty = false
    local function _ue_clean(s)
        if type(s) ~= "string" then return s end
        s = string_gsub(s, "%%", "")
        s = string_gsub(s, "\\", "")
        return (string_gsub(s, rule.action.fix_matched_parts.remove_chars_pattern, ""))
    end
    for _, mp in pairs(matched_parts) do

        -- path
        local m = string_match(mp.matched_on, '^request%.raw%_path$')
        if m then
            local raw_path = kong.request.get_raw_path()
            raw_path = string_gsub(raw_path, "%%", "")
            raw_path = string_gsub(raw_path, "\\", "")
            raw_path = string_gsub(raw_path, rule.action.fix_matched_parts.remove_chars_pattern, "")
            kong.service.request.set_path(raw_path)
        end

        -- querystring entry
        m = string_match(mp.matched_on, '^request%.query%.value%:(.+)$')
        if m then
            local qs = kong.request.get_query()
            if qs then
                for k, _ in pairs(qs) do
                    if k == m then
                        qs[k] = string_gsub(qs[k], "%%", "")
                        qs[k] = string_gsub(qs[k], "\\", "")
                        qs[k] = string_gsub(qs[k], rule.action.fix_matched_parts.remove_chars_pattern, "")
                    end
                end
                kong.service.request.set_query(qs)
            end
        end

        -- request header value
        m = string_match(mp.matched_on, '^request%.header%.value%:(.+)$')
        if m then
            local matched_header_value = request_get_header(m)
            if matched_header_value then
                matched_header_value = string_gsub(matched_header_value, "%%", "")
                matched_header_value = string_gsub(matched_header_value, "\\", "")
                matched_header_value = string_gsub(matched_header_value, rule.action.fix_matched_parts.remove_chars_pattern, "")
                kong.service.request.set_header(m, matched_header_value)
            end
        end

        -- urlencoded body field: per-value sanitize, structure preserved.
        -- Match both `.value:<name>` and `.name:<name>` (request.arg.value:x
        -- resolves to both; pairs() order is non-deterministic).
        local ub = string_match(mp.matched_on, '^request%.body%.urlencode%.[^:]+:(.+)$')
        if ub then
            if ue_body == nil then
                ue_body = kong.request.get_body("application/x-www-form-urlencoded") or false
            end
            if type(ue_body) == "table" and ue_body[ub] ~= nil then
                local v = ue_body[ub]
                if type(v) == "table" then
                    for i, vv in ipairs(v) do v[i] = _ue_clean(vv) end
                else
                    ue_body[ub] = _ue_clean(v)
                end
                ue_dirty = true
            end

        -- generic body (scalar request.body / json / multipart / xml): raw strip
        elseif string_match(mp.matched_on, '^request%.body') then
            local body = request_get_raw_body()
            if body then
                body = string_gsub(body, "%%", "")
                body = string_gsub(body, "\\", "")
                body = string_gsub(body, rule.action.fix_matched_parts.remove_chars_pattern, "")
                kong.service.request.set_raw_body(body)
            end
        end
    end

    if ue_dirty and type(ue_body) == "table" then
        kong.service.request.set_body(ue_body, "application/x-www-form-urlencoded")
    end
end

-- ============================================================
-- assertions
-- ============================================================
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
-- test cases
-- ============================================================
local SHELLY_PATTERN  = "[<>\"';&|`%$()]"  -- generic injection-shape chars
local APOS_PATTERN    = "[']"               -- apostrophe-only (SQLi-shape)
local LT_GT_PATTERN   = "[<>]"              -- XSS-shape

print("- path sanitize: /a';drop_table--/ → /adrop_table--/")
reset_mocks()
recorded.raw_path_returns = "/a';drop_table--/"
fix_matching_parts(
    { action = { fix_matched_parts = { remove_chars_pattern = SHELLY_PATTERN } } },
    { { matched_on = "request.raw_path", matched_value = "/a';drop_table--/" } }
)
ok(recorded.path == "/adrop_table--/", "path stripped (was: " .. tostring(recorded.path) .. ")")

print("- querystring sanitize: name=O'Brien → name=OBrien (proper name)")
reset_mocks()
recorded.query_returns = { name = "O'Brien" }
fix_matching_parts(
    { action = { fix_matched_parts = { remove_chars_pattern = APOS_PATTERN } } },
    { { matched_on = "request.query.value:name", matched_value = "O'Brien" } }
)
ok(recorded.query and recorded.query.name == "OBrien",
   "name sanitized (was: " .. tostring(recorded.query and recorded.query.name) .. ")")

print("- querystring sanitize: address=Via dell'Orso, 5 → Via dellOrso, 5")
reset_mocks()
recorded.query_returns = { address = "Via dell'Orso, 5" }
fix_matching_parts(
    { action = { fix_matched_parts = { remove_chars_pattern = APOS_PATTERN } } },
    { { matched_on = "request.query.value:address", matched_value = "Via dell'Orso, 5" } }
)
ok(recorded.query and recorded.query.address == "Via dellOrso, 5",
   "address sanitized (was: " .. tostring(recorded.query and recorded.query.address) .. ")")

print("- querystring sanitize ignores other keys")
reset_mocks()
recorded.query_returns = { name = "O'Brien", other = "Don't touch this'" }
fix_matching_parts(
    { action = { fix_matched_parts = { remove_chars_pattern = APOS_PATTERN } } },
    { { matched_on = "request.query.value:name", matched_value = "O'Brien" } }
)
ok(recorded.query.name == "OBrien", "matched key sanitized")
ok(recorded.query.other == "Don't touch this'", "unmatched key untouched")

print("- header sanitize: X-Filename=<script> → script")
reset_mocks()
recorded.header_returns["x-filename"] = "<script>alert(1)</script>"
fix_matching_parts(
    { action = { fix_matched_parts = { remove_chars_pattern = LT_GT_PATTERN } } },
    { { matched_on = "request.header.value:x-filename", matched_value = "<script>alert(1)</script>" } }
)
ok(recorded.headers["x-filename"] == "scriptalert(1)/script",
   "header stripped (was: " .. tostring(recorded.headers["x-filename"]) .. ")")

print("- body sanitize: <script>alert(1)</script>&name=ok → scriptalert(1)/scriptname=ok")
reset_mocks()
recorded.body_returns = "<script>alert(1)</script>&name=ok"
fix_matching_parts(
    { action = { fix_matched_parts = { remove_chars_pattern = "[<>&]" } } },
    { { matched_on = "request.body", matched_value = "..." } }
)
ok(recorded.body == "scriptalert(1)/scriptname=ok",
   "body stripped (was: " .. tostring(recorded.body) .. ")")

print("- hardcoded strip: %5C and %% always stripped before pattern")
reset_mocks()
recorded.query_returns = { x = "a%bb\\c" }
fix_matching_parts(
    { action = { fix_matched_parts = { remove_chars_pattern = "" } } },
    { { matched_on = "request.query.value:x", matched_value = "a%bb\\c" } }
)
ok(recorded.query.x == "abbc",
   "default strips %% and backslash even with empty pattern (got: " .. tostring(recorded.query.x) .. ")")

print("- urlencoded body field: user=andrea' OR 1=1-- → value sanitized, form kept")
reset_mocks()
recorded.body_form_returns = { user = "andrea' OR 1=1-- ", password = "1234" }
fix_matching_parts(
    { action = { fix_matched_parts = { remove_chars_pattern = "[-\"';=()|]" } } },
    { { matched_on = "request.body.urlencode.value:user", matched_value = "andrea' OR 1=1-- " } }
)
ok(recorded.body == nil, "raw body NOT rewritten (per-field path taken, structure preserved)")
ok(recorded.body_form and recorded.body_form.user == "andrea OR 11 ",
   "user value sanitized (got: " .. tostring(recorded.body_form and recorded.body_form.user) .. ")")
ok(recorded.body_form and recorded.body_form.password == "1234",
   "password field untouched (got: " .. tostring(recorded.body_form and recorded.body_form.password) .. ")")

print("- urlencoded body via NAME key (race path): still sanitizes the field value")
reset_mocks()
recorded.body_form_returns = { user = "andrea' OR 1=1-- ", password = "1234" }
fix_matching_parts(
    { action = { fix_matched_parts = { remove_chars_pattern = "[-\"';=()|]" } } },
    { { matched_on = "request.body.urlencode.name:user", matched_value = "user" } }
)
ok(recorded.body == nil, "raw body NOT rewritten on the name-key path either")
ok(recorded.body_form and recorded.body_form.user == "andrea OR 11 ",
   "name-key path sanitizes the field VALUE (got: " .. tostring(recorded.body_form and recorded.body_form.user) .. ")")

print("- no match on unknown surface → silent no-op")
reset_mocks()
recorded.raw_path_returns = "/x"
fix_matching_parts(
    { action = { fix_matched_parts = { remove_chars_pattern = "[xyz]" } } },
    { { matched_on = "request.something.weird", matched_value = "..." } }
)
ok(recorded.path == nil, "untouched surface produces no set_path")
ok(recorded.query == nil, "untouched surface produces no set_query")
ok(next(recorded.headers) == nil, "untouched surface produces no set_header")
ok(recorded.body == nil, "untouched surface produces no set_raw_body")

print(string.format("\n%d test(s) failed", fails))
os.exit(fails == 0 and 0 or 1)
