-- ka-unittest/multipart_file_head.lua
--
-- request.body.multipart.file_head: the first 64 bytes of every uploaded file
-- (a multipart part with `filename=`), so a rule can check magic bytes on
-- every upload without knowing the field names and without scanning whole
-- files.
--
-- Pinned here:
--   1. the collection covers every file part, whatever its field name, and
--      every duplicate (`<name>:<n>`) in any position;
--   2. only the first 64 bytes: a marker further in is not seen (by design),
--      a file shorter than that is exposed whole, an empty file keeps its key
--      with an empty value;
--   3. a part without `filename=` is not in file_head (it stays in ARGS);
--   4. file_head is NOT in ARGS: a rule on request.arg.value never sees it,
--      and the RE2 pre-pass resolver leaves it out;
--   5. a non-multipart request resolves to nothing;
--   6. the named selector `request.body.multipart.file_head:<name>` works,
--      duplicates included, and an exclusion removes it;
--   7. a match on file content is flagged as unsanitizable
--      (`__matches_upload_content`), so fix_matched_parts blocks instead;
--   8. the ARGS merge and the pre-pass filter are anchored on the multipart
--      prefix: an urlencoded or JSON key that merely contains
--      `.file_content:` / `.file_head:` stays in ARGS.
--
-- Run from repo root:
--   lua    ka-unittest/multipart_file_head.lua
--   luajit ka-unittest/multipart_file_head.lua

package.path = "./kong/plugins/karna/modules/?.lua;" .. package.path

-- Real multipart parser under the engine harness (see
-- duplicate_key_collisions.lua for why it is loaded first).
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

local PS     = "%!PS-Adobe-3.0\n%%BoundingBox: 0 0 10 10\nshowpage\n"
local PS_CTL = "\4%!PS-Adobe-3.0\n"
local EPS    = "\197\208\211\198" .. string.rep("\0", 28)
local JPEG   = "\255\216\255\224\0\16JFIF\0" .. string.rep("x", 100)
local PNG    = "\137PNG\r\n\26\n" .. string.rep("y", 100)
local PDF    = "%PDF-1.7\n" .. string.rep("z", 100)

local function cond(variable, op, value)
    return { id = "900950", phase = "access", tags = {},
             conditions = { { variables = { variable }, op = op, value = value, transform = {} } } }
end

-- ModSecurity-style "starts with any of": one rule per prefix, any fires
local function ps_rule_matches()
    for _, prefix in ipairs({ "%!", "\4%!", "\197\208\211\198" }) do
        if H.match(cond("request.body.multipart.file_head", "beginsWith", prefix)) then return true end
    end
    return false
end

local B = "XBOUNDARYX"
local function mp(parts)
    local out = {}
    for _, p in ipairs(parts) do
        local cd = 'form-data; name="' .. p[1] .. '"'
        if p.file then cd = cd .. '; filename="' .. p.file .. '"' end
        out[#out + 1] = "--" .. B .. "\r\nContent-Disposition: " .. cd .. "\r\n"
        if p.file then out[#out + 1] = "Content-Type: " .. (p.ct or "image/jpeg") .. "\r\n" end
        out[#out + 1] = "\r\n" .. p[2] .. "\r\n"
    end
    out[#out + 1] = "--" .. B .. "--\r\n"
    return table.concat(out)
end

local function set_mp(parts)
    local body = mp(parts)
    H.request.method    = "POST"
    H.request.path      = "/upload"
    H.request.raw_path  = "/upload"
    H.request.raw_query = ""
    H.request.headers   = { ["Content-Type"] = "multipart/form-data; boundary=" .. B,
                            ["Content-Length"] = tostring(#body) }
    H.request.body      = body
    H.request.body_file = nil
    H.reset()
end

local function set_other(ct, body, query)
    H.request.method    = body and "POST" or "GET"
    H.request.path      = "/x"
    H.request.raw_path  = "/x"
    H.request.raw_query = query or ""
    H.request.headers   = {}
    if ct then H.request.headers["Content-Type"] = ct end
    if body then H.request.headers["Content-Length"] = tostring(#body) end
    H.request.body      = body
    H.request.body_file = nil
    H.reset()
end

local function file_heads()
    local out = {}
    for k, v in pairs(engine.__get_values_request_body(false) or {}) do
        if string.find(k, "request.body.multipart.file_head:", 1, true) == 1 then out[k] = v end
    end
    return out
end

-- ===========================================================================
print("- 1. every file part, any field name, every duplicate")
-- ===========================================================================
for _, name in ipairs({ "async-upload", "foo", "x[]" }) do
    set_mp({ { name, PS, file = "a.jpg" } })
    ok(ps_rule_matches(), "PostScript upload under field '" .. name .. "' matches")
end
set_mp({ { "f", PS_CTL, file = "a.jpg" } })
ok(ps_rule_matches(), "\\x04%! prefix matches")
set_mp({ { "f", EPS, file = "a.eps" } })
ok(ps_rule_matches(), "C5 D0 D3 C6 prefix matches")

for _, pos in ipairs({ 2, 3, 10 }) do
    local parts = {}
    for i = 1, pos do parts[i] = { "upload", (i == pos) and PS or JPEG, file = "p" .. i .. ".jpg" } end
    set_mp(parts)
    ok(ps_rule_matches(), "same field name, PostScript in position " .. pos)
end
set_mp({ { "photo", JPEG, file = "a.jpg" }, { "avatar", PS, file = "b.jpg" } })
ok(ps_rule_matches(), "two different fields, PostScript in the second")
set_mp({ { "a", JPEG, file = "a.jpg" }, { "a", PS, file = "b.jpg" }, { "a:2", JPEG, file = "c.jpg" } })
ok(ps_rule_matches(), "a literal `a:2` part does not hide the second `a`")

-- ===========================================================================
print("- 2. only the first 64 bytes")
-- ===========================================================================
for label, content in pairs({ JPEG = JPEG, PNG = PNG, PDF = PDF }) do
    set_mp({ { "f", content, file = "x" } })
    ok(not ps_rule_matches(), "clean " .. label .. " does not match")
end
set_mp({ { "f", string.rep("A", 100) .. "%!PS", file = "a.jpg" } })
ok(not ps_rule_matches(), "a marker at offset 100 is not seen (by design)")
local heads = file_heads()
ok(#(heads["request.body.multipart.file_head:f"] or "") == 64, "the head is exactly 64 bytes",
   #(heads["request.body.multipart.file_head:f"] or ""))
set_mp({ { "f", "%!", file = "tiny.ps" } })
ok(file_heads()["request.body.multipart.file_head:f"] == "%!", "a file shorter than 64 bytes is exposed whole")
set_mp({ { "f", "", file = "empty.jpg" } })
heads = file_heads()
ok(heads["request.body.multipart.file_head:f"] == "", "an empty file keeps its key with an empty value",
   tostring(heads["request.body.multipart.file_head:f"]))
ok(not ps_rule_matches(), "an empty file matches nothing")

-- ===========================================================================
print("- 3. a part without filename= is not a file")
-- ===========================================================================
set_mp({ { "comment", PS } })
ok(next(file_heads()) == nil, "no file_head key for a form field")
ok(not ps_rule_matches(), "the file_head rule does not fire on a form field")
ok(H.match(cond("request.arg.value", "beginsWith", "%!")), "the form field stays in ARGS")

-- ===========================================================================
print("- 4. file_head is not in ARGS, nor in the RE2 pre-pass")
-- ===========================================================================
set_mp({ { "f", PS, file = "a.jpg" } })
ok(not H.match(cond("request.arg.value", "contains", "%!PS")), "a rule on ARGS never sees file bytes")
local re2_gate = dofile("./kong/plugins/karna/modules/ka_re2_gate.lua")
local scanned = re2_gate._body_values_no_file(engine) or {}
local in_scan = false
for k in pairs(scanned) do
    if string.find(k, "request.body.multipart.file_", 1, true) == 1 then in_scan = true end
end
ok(not in_scan, "the RE2 pre-pass body resolver leaves file_head / file_content out")
ok(scanned["request.body.multipart.filename:f"] == "a.jpg", "the filename stays in the pre-pass")
local args = engine:__get_values_request_args(false, nil) or {}
local leaked = false
for k in pairs(args) do if string.find(k, "file_head", 1, true) then leaked = true end end
ok(not leaked, "no file_head key in the ARGS map")

-- ===========================================================================
print("- 5. a non-multipart request resolves to nothing")
-- ===========================================================================
set_other("application/x-www-form-urlencoded", "a=%25!PS")
ok(not ps_rule_matches(), "urlencoded body")
set_other("application/json", '{"a":"%!PS"}')
ok(not ps_rule_matches(), "JSON body")
set_other(nil, nil, "a=%25!PS")
ok(not ps_rule_matches(), "GET with a query")

-- ===========================================================================
print("- 6. named selector and exclusion")
-- ===========================================================================
set_mp({ { "f", JPEG, file = "a.jpg" }, { "f", PS, file = "b.jpg" } })
ok(H.match(cond("request.body.multipart.file_head:f", "beginsWith", "%!")),
   "file_head:<name> includes the duplicate")
ok(not H.match(cond("request.body.multipart.file_head:g", "beginsWith", "%!")),
   "file_head:<other name> does not match")
local copy = {}
for k, v in pairs(file_heads()) do copy[k] = v end
engine.__remove_ctl_target(copy, "request.body.multipart.file_head:f", "request.body.multipart.file_head")
ok(next(copy) == nil, "an exclusion of file_head:f removes both occurrences")

-- ===========================================================================
print("- 7. fix_matched_parts cannot sanitize file content")
-- ===========================================================================
ok(engine.__matches_upload_content({ { matched_on = "request.body.multipart.file_head:f" } }),
   "file_head match is upload content")
ok(engine.__matches_upload_content({ { matched_on = "request.body.multipart.file_content:f:2" } }),
   "file_content match is upload content")
ok(not engine.__matches_upload_content({ { matched_on = "request.body.multipart.value:f" } }),
   "a form field match is not")
ok(not engine.__matches_upload_content({ { matched_on = "request.body.urlencode.value:x.file_head:y" } }),
   "a key that merely contains the marker is not")

-- ===========================================================================
print("- 8. the file-content filters are anchored")
-- ===========================================================================
set_other("application/x-www-form-urlencoded", "a.file_content:b=KAMARK1&c.file_head:d=KAMARK2")
ok(H.match(cond("request.arg.value", "contains", "KAMARK1")), "urlencoded `a.file_content:b` stays in ARGS")
ok(H.match(cond("request.arg.value", "contains", "KAMARK2")), "urlencoded `c.file_head:d` stays in ARGS")
set_other("application/json", '{"a":{"file_content:b":"KAMARK3"}}')
ok(H.match(cond("request.arg.value", "contains", "KAMARK3")), "JSON key `file_content:b` stays in ARGS")

print("")
if fails > 0 then
    print(fails .. " FAILED")
    os.exit(1)
end
print("all passed")
