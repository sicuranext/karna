-- ka-unittest/duplicate_key_collisions.lua
--
-- Repeated argument / part / cookie names, and names that look like the
-- engine's duplicate index.
--
-- A repeated name is keyed `<name>` for its first occurrence and `<name>:<n>`
-- for the next ones. The client picks the names, so `a:2` can also arrive as
-- a literal name. Before the fix:
--   * urlencoded body and query: `a:2=<payload>&a=x&a=y` wrote the third
--     occurrence over the literal's value, so the payload left ARGS while the
--     backend still received it;
--   * multipart: the per-part rows are flattened last-wins, so `a`,
--     `a=<payload>`, `a:2` dropped the payload from ARGS while a last-wins
--     backend (PHP) read exactly it. The same hid a file part's filename and
--     content (`f=a.jpg`, `f=shell.php`, `f:2=c.jpg`);
--   * cookies: only the first occurrence of a name was kept, so
--     `c=clean; c=<payload>` was never inspected;
--   * the named selectors (`request.arg.value:a`, `request.query.value:a`,
--     `request.cookie.value:a`, `request.body.multipart.<x>:a`) matched only
--     the plain key, so a rule written for `a` never saw the second `a`,
--     while the target-removal applier already stripped `a:<n>` too.
--
-- Pinned here: every occurrence stays inspectable in the collections and in
-- the named selectors (dispatcher and compiled resolver), an exclusion strips
-- the duplicates too (cookie JSON expansion included), and the single-name
-- cases are unchanged. Same family: the filter that keeps uploaded file bytes
-- out of ARGS matched `.file_content:` anywhere in a key, so an urlencoded
-- `a.file_content:b` or a JSON key `file_content:b` left ARGS too (section 8).
--
-- Run from repo root:
--   lua    ka-unittest/duplicate_key_collisions.lua
--   luajit ka-unittest/duplicate_key_collisions.lua

package.path = "./kong/plugins/karna/modules/?.lua;" .. package.path

-- The engine harness stubs ka_multipart out. Load the real parser first, with
-- the same ngx.re shim multipart_security_gaps.lua uses (ka_multipart captures
-- ngx.re.match at load time), and register it so the harness's stub is never
-- required.
_G.ngx = {
    re = {
        match = function(s, pattern, _flags)
            if pattern == [[;\s*boundary\s*=\s*([0-9a-zA-Z'()+_,./:=?-]+)]] then
                local b = s:match(";%s*boundary%s*=%s*([0-9a-zA-Z'()+_,./:=?%-]+)")
                if b then return { b } end
                return nil
            end
            if pattern == "%[0-9a-fA-F][0-9a-fA-F]" then
                return s:match("%%[0-9a-fA-F][0-9a-fA-F]") and { true } or nil
            end
            if pattern == "\\0" then
                return s:find("\0", 1, true) and { true } or nil
            end
            return nil
        end,
    },
}
package.preload["inspect"] = function() return function() return "" end end
package.loaded["kong.plugins.karna.ka_multipart"] = dofile("./kong/plugins/karna/modules/ka_multipart.lua")

local H = dofile("./ka-unittest/_engine_harness.lua")
local engine = H.engine

local fails = 0
local function ok(cond, name, detail)
    if cond then print("  ok  - " .. name)
    else print("  FAIL- " .. name .. (detail and ("  (" .. tostring(detail) .. ")") or "")); fails = fails + 1 end
end

local EVIL = "KAEVILMARK"

local function rule(variable, value)
    return {
        id = "900900", phase = "access", tags = {},
        conditions = { { variables = { variable }, op = "contains", value = value or EVIL, transform = {} } },
    }
end

local function set_request(method, ct, body, query, cookie)
    H.request.method    = method
    H.request.path      = "/x"
    H.request.raw_path  = "/x"
    H.request.raw_query = query or ""
    H.request.headers   = {}
    if ct then H.request.headers["Content-Type"] = ct end
    if body then H.request.headers["Content-Length"] = tostring(#body) end
    if cookie then H.request.headers["Cookie"] = cookie end
    H.request.body      = body
    H.request.body_file = nil
end

-- one rule through the dispatcher and through the compiled resolver
local function both(name, req, variable, expected, value)
    for _, path in ipairs({ "dispatcher", "compiled" }) do
        req()
        H.reset()
        local r = rule(variable, value)
        if path == "compiled" then H.attach_resolvers(r) end
        local got = H.match(r) and true or false
        ok(got == expected, name .. " [" .. path .. "]", "got " .. tostring(got))
    end
end

local function count_with(map, needle)
    local n = 0
    for _, v in pairs(map or {}) do
        if string.find(tostring(v), needle, 1, true) then n = n + 1 end
    end
    return n
end

local UE = "application/x-www-form-urlencoded"
local B = "XBOUNDARYX"
local MP = "multipart/form-data; boundary=" .. B

local function mp(parts)
    local out = {}
    for _, p in ipairs(parts) do
        local cd = 'form-data; name="' .. p[1] .. '"'
        if p.file then cd = cd .. '; filename="' .. p.file .. '"' end
        out[#out + 1] = "--" .. B .. "\r\nContent-Disposition: " .. cd .. "\r\n"
        if p.file then out[#out + 1] = "Content-Type: image/jpeg\r\n" end
        out[#out + 1] = "\r\n" .. p[2] .. "\r\n"
    end
    out[#out + 1] = "--" .. B .. "--\r\n"
    return table.concat(out)
end

-- ===========================================================================
print("- 1. urlencoded body: a literal `a:2` never loses its value")
-- ===========================================================================
local function ue(body) return function() set_request("POST", UE, body) end end
both("a=clean&a=EVIL (control)", ue("a=clean&a=" .. EVIL), "request.arg.value", true)
both("a=clean&a=EVIL&a:2=clean", ue("a=clean&a=" .. EVIL .. "&a:2=clean"), "request.arg.value", true)
both("a:2=EVIL&a=clean&a=clean", ue("a:2=" .. EVIL .. "&a=clean&a=clean"), "request.arg.value", true)
both("a%3a2=EVIL&a=clean&a=clean (encoded colon)", ue("a%3a2=" .. EVIL .. "&a=clean&a=clean"), "request.arg.value", true)

set_request("POST", UE, "a:2=x1&a=x2&a=x3&a:2=x4&a=x5")
H.reset()
local body = engine.__get_values_request_body(false)
for _, v in ipairs({ "x1", "x2", "x3", "x4", "x5" }) do
    ok(count_with(body, v) == 1, "every occurrence kept once: " .. v)
end
local names = 0
for k in pairs(body) do if string.find(k, ".name:", 1, true) then names = names + 1 end end
ok(names == 5, "five name keys for five arguments (limit_arg_num counts them all)", names)

-- ===========================================================================
print("- 2. query string: same parser, same guarantee")
-- ===========================================================================
local function q(query) return function() set_request("GET", nil, nil, query) end end
both("query a:2=EVIL&a=clean&a=clean", q("a:2=" .. EVIL .. "&a=clean&a=clean"), "request.arg.value", true)
both("query a:2=EVIL&a=clean&a=clean, request.query.value", q("a:2=" .. EVIL .. "&a=clean&a=clean"), "request.query.value", true)

-- ===========================================================================
print("- 3. multipart: a part never overwrites another part's keys")
-- ===========================================================================
local function mpr(parts) return function() set_request("POST", MP, mp(parts)) end end
both("a=clean, a=EVIL (control)", mpr({ { "a", "clean" }, { "a", EVIL } }), "request.arg.value", true)
both("a=clean, a=EVIL, a:2=clean", mpr({ { "a", "clean" }, { "a", EVIL }, { "a:2", "clean" } }), "request.arg.value", true)
both("a:2=EVIL, a=clean, a=clean", mpr({ { "a:2", EVIL }, { "a", "clean" }, { "a", "clean" } }), "request.arg.value", true)
both("a=clean, a=EVIL, A:2=clean (names are lowercased)", mpr({ { "a", "clean" }, { "a", EVIL }, { "A:2", "clean" } }), "request.arg.value", true)

local files = { { "f", "x", file = "a.jpg" }, { "f", "x", file = "shell.php" }, { "f", "x", file = "c.jpg" } }
files[3][1] = "f:2"
both("files f=a.jpg, f=shell.php, f:2=c.jpg: request.file sees shell.php", mpr(files), "request.file", true, "shell.php")
both("same: request.body.multipart.filename sees shell.php", mpr(files), "request.body.multipart.filename", true, "shell.php")

set_request("POST", MP, mp(files))
H.reset()
body = engine.__get_values_request_body(false)
local fnames = {}
for k, v in pairs(body) do
    if string.find(k, "request.body.multipart.filename:", 1, true) == 1 then fnames[#fnames + 1] = v end
end
table.sort(fnames)
ok(table.concat(fnames, ",") == "a.jpg,c.jpg,shell.php", "all three filenames are kept", table.concat(fnames, ","))
local fc = 0
for k in pairs(body) do if string.find(k, ".file_content:", 1, true) then fc = fc + 1 end end
ok(fc == 3, "three file parts, three file_content keys", fc)

-- ===========================================================================
print("- 4. cookies: every occurrence of a name is kept")
-- ===========================================================================
local function ck(cookie) return function() set_request("GET", nil, nil, nil, cookie) end end
both("c=EVIL (control)", ck("c=" .. EVIL), "request.cookie.value", true)
both("c=clean; c=EVIL", ck("c=clean; c=" .. EVIL), "request.cookie.value", true)
both("c=clean; c=EVIL; c:2=clean", ck("c=clean; c=" .. EVIL .. "; c:2=clean"), "request.cookie.value", true)
both("c:2=EVIL; c=clean; c=clean", ck("c:2=" .. EVIL .. "; c=clean; c=clean"), "request.cookie.value", true)
both('JSON cookies c={"x":"clean"}; c={"x":"EVIL"}', ck('c={"x":"clean"}; c={"x":"' .. EVIL .. '"}'), "request.cookie.value", true)

set_request("GET", nil, nil, nil, "c=one; c=two; C=three")
H.reset()
local jar = engine.__get_values_request_cookie(false)
ok(jar["request.cookie.value:c"] == "one", "the first occurrence keeps the plain key", jar["request.cookie.value:c"])
ok(jar["request.cookie.value:c:2"] == "two" and jar["request.cookie.value:c:3"] == "three",
   "the next ones are indexed in order")

-- ===========================================================================
print("- 5. named selectors include the duplicates")
-- ===========================================================================
both("request.arg.value:a, query a=clean&a=EVIL", q("a=clean&a=" .. EVIL), "request.arg.value:a", true)
both("request.arg.value:a, body a=clean&a=EVIL", ue("a=clean&a=" .. EVIL), "request.arg.value:a", true)
both("request.query.value:a, query a=clean&a=EVIL", q("a=clean&a=" .. EVIL), "request.query.value:a", true)
both("request.cookie.value:c, c=clean; c=EVIL", ck("c=clean; c=" .. EVIL), "request.cookie.value:c", true)
both('request.cookie.value:c, JSON duplicate', ck('c={"x":"clean"}; c={"x":"' .. EVIL .. '"}'), "request.cookie.value:c", true)
both("request.body.multipart.value:a, a=clean, a=EVIL", mpr({ { "a", "clean" }, { "a", EVIL } }), "request.body.multipart.value:a", true)
both("request.body.multipart.filename:f sees shell.php", mpr(files), "request.body.multipart.filename:f", true, "shell.php")
-- unchanged single-name behaviour
both("request.arg.value:a does not match another name (ab)", q("ab=" .. EVIL), "request.arg.value:a", false)
both("request.arg.value:a does not match a:b", q("a:b=" .. EVIL), "request.arg.value:a", false)
both("request.cookie.value:c does not match cc", ck("cc=" .. EVIL), "request.cookie.value:c", false)

-- ===========================================================================
print("- 6. an exclusion strips the duplicates too")
-- ===========================================================================
set_request("GET", nil, nil, nil, 'c={"x":"1"}; c={"x":"' .. EVIL .. '"}; c=plain; d=keep')
H.reset()
local copy = {}
for k, v in pairs(engine.__get_values_request_cookie(false)) do copy[k] = v end
engine.__remove_ctl_target(copy, "request.cookie.value:c", "request.cookie.value")
local left_c = 0
for k in pairs(copy) do
    if string.find(k, "json.c", 1, true) or string.find(k, "value:c", 1, true) then left_c = left_c + 1 end
end
ok(left_c == 0, "no value / JSON key of cookie c survives the exclusion", left_c)
ok(copy["request.cookie.value:d"] == "keep", "another cookie is untouched")

set_request("POST", UE, "a=1&a=" .. EVIL .. "&b=keep")
H.reset()
copy = {}
for k, v in pairs(engine.__get_values_request_body(false)) do copy[k] = v end
engine.__remove_ctl_target(copy, "request.arg.value:a", "request.arg.value")
ok(count_with(copy, EVIL) == 0, "request.arg.value:a exclusion strips a:2")
ok(count_with(copy, "keep") == 1, "b is untouched")

-- ===========================================================================
print("- 7. JSON collisions still fail closed")
-- ===========================================================================
set_request("POST", "application/json", '{"a":{"b":"clean"},"a.b":"' .. EVIL .. '"}')
H.reset()
local _, jerr = engine.__get_values_request_body(false)
ok(jerr ~= nil, "flattened key collision is a parse error (blocked by the body parser gate)", jerr)

-- ===========================================================================
print("- 8. the file-content filter is anchored on the multipart prefix")
-- ===========================================================================
both("urlencoded `a.file_content:b` stays in ARGS", function() set_request("POST", UE, "a.file_content:b=" .. EVIL) end,
     "request.arg.value", true)
both('JSON key `file_content:b` stays in ARGS',
     function() set_request("POST", "application/json", '{"a":{"file_content:b":"' .. EVIL .. '"}}') end,
     "request.arg.value", true)
set_request("POST", MP, mp({ { "f", EVIL, file = "a.jpg" } }))
H.reset()
ok(not H.match(rule("request.arg.value")), "a real uploaded file is still out of ARGS")

print("")
if fails > 0 then
    print(fails .. " FAILED")
    os.exit(1)
end
print("all passed")
