-- ka-unittest/arg_name_pattern_chars.lua
--
-- An arg whose value is JSON and whose NAME carries Lua pattern magic
-- characters (`facets[]={...}`) 500'd the request in 1.7.1:
--
--   ka_body_parser.lua:247: malformed pattern (missing ']')
--
-- The nested-JSON flattener spliced its prefix, which embeds the client's arg
-- name (`request.query.json:facets[]`), into a gsub pattern with only the dots
-- escaped. `[` broke the pattern; `-`, `+`, `*`, `?` silently missed and left
-- the derived keys unstripped (`request.query.json:my-f.value:.field`).
--
-- Pinned here:
--   1. three query strings shaped like the production ones parse with no Lua error;
--   2. the arrays and repeated names are all there (`facets[]`,
--      `primaryfilters[]`, `dates[]` twice, …), and the nested JSON keys get
--      the right `.value:` / `.name:` shape;
--   3. names with `-`, `+`, `%`, `(`, `?`, `$`, `^`, `*` get the same shape;
--   4. rules still see the values: a `contains` over ARGS / the query collection
--      catches a SQLi payload inside `facets[]` (raw arg and nested JSON key);
--   5. a Lua error inside the JSON flattener fails the parse (the raw value
--      stays inspectable) instead of escaping to the caller.
--
-- Run from repo root:
--   lua    ka-unittest/arg_name_pattern_chars.lua
--   luajit ka-unittest/arg_name_pattern_chars.lua

local H = dofile("./ka-unittest/_engine_harness.lua")
local engine, bp = H.engine, H.body_parser

local fails = 0
local function ok(cond, name, detail)
    if cond then print("  ok  - " .. name)
    else print("  FAIL- " .. name .. (detail and ("  (" .. tostring(detail) .. ")") or "")); fails = fails + 1 end
end

local Q1 = "type=poi+city+region&typePage=places&facets[]=%7B%22field%22:%22places_lcs%22,%22selectedValues%22:[%22%2Fsites%2Fshop%2F.content%2Fregion%2Fregion_00006.xml%22]%7D&locale=en&activeFilter[]=%7B%7D&showDateBox=false&showFilters=true&page=1&prices=%7B%22value%22:null%7D&defaultsort=title_asc&activeFacets[]=destination"
local Q2 = "type=product&locale=en&activeFilter[]=%7B%7D&showDateBox=true&showFilters=true&page=1&primaryFilters[]=%7B%22name%22:%22Single%22,%22value%22:%22%2Fsystem%2Fcategories%2Ftarget%2Fsingle%2F%22,%22field%22:%22target_lcs%22,%22active%22:true%7D&prices=%7B%22value%22:null%7D&products=%2F.categories%2Fproduct%2Fcard%2F,%2F.categories%2Fproduct%2Feducational%2Fslots%2F,%2F.categories%2Fproduct%2Fticket%2F&defaultsort=title_asc&activeFacets[]=destination"
local Q3 = "type=product&dates[]=1792620000000&dates[]=1792706399000&locale=en&activeFilter[]=%7B%7D&facets[]=%7B%22a%22:1%7D&facets[]=%7B%22a%22:2%7D"

local function parse(q)
    local pok, values, err = pcall(bp.urlencoded, bp, "request.query", q, false)
    return pok, values, err
end

-- ===========================================================================
print("- 1. production-shaped query strings parse without a Lua error")
-- ===========================================================================
local parsed = {}
for i, q in ipairs({ Q1, Q2, Q3 }) do
    local pok, values, err = parse(q)
    ok(pok and type(values) == "table", "query " .. i .. " parses", pok and err or values)
    parsed[i] = pok and values or {}
end

-- ===========================================================================
print("- 2. arrays, repeated names and nested JSON keys")
-- ===========================================================================
local v1, v2, v3 = parsed[1], parsed[2], parsed[3]
ok(v1["request.query.value:facets[]"] ==
   '{"field":"places_lcs","selectedValues":["/sites/shop/.content/region/region_00006.xml"]}',
   "facets[] raw value", v1["request.query.value:facets[]"])
ok(v1["request.query.json:facets[].value:field"] == "places_lcs",
   "facets[] nested field value", v1["request.query.json:facets[].value:field"])
ok(v1["request.query.json:facets[].name:field"] == "field",
   "facets[] nested field name", v1["request.query.json:facets[].name:field"])
ok(v1["request.query.json:facets[].value:selectedvalues.1"] ==
   "/sites/shop/.content/region/region_00006.xml",
   "facets[] nested array element")
ok(v1["request.query.value:activefacets[]"] == "destination", "activeFacets[]")
ok(v1["request.query.value:prices"] == '{"value":null}', "prices raw value")
for k in pairs(v1) do
    if k:find(".value:.", 1, true) then ok(false, "no unstripped derived key", k) end
end

ok(v2["request.query.json:primaryfilters[].value:name"] == "Single", "primaryFilters[] name")
ok(v2["request.query.json:primaryfilters[].value:active"] == "true", "primaryFilters[] active")
ok(v2["request.query.value:products"] ~= nil, "products")

ok(v3["request.query.value:dates[]"] == "1792620000000", "dates[] first")
ok(v3["request.query.value:dates[]:2"] == "1792706399000", "dates[] second")
ok(v3["request.query.json:facets[].value:a"] == "1", "repeated JSON arg, first wins on the derived key")
ok(v3["request.query.value:facets[]:2"] == '{"a":2}', "repeated JSON arg, second raw value kept")

-- ===========================================================================
print("- 3. other magic characters in the name")
-- ===========================================================================
for _, name in ipairs({ "my-f", "a+b", "a%25b", "f(x)", "q%3F", "p$", "^h", "s*", "x]", "%5Bopen" }) do
    local pok, values = parse(name .. "=%7B%22k%22:%22v%22%7D")
    local lname = ngx.unescape_uri(name):lower()
    ok(pok and values["request.query.json:" .. lname .. ".value:k"] == "v"
           and values["request.query.json:" .. lname .. ".name:k"] == "k",
       "name " .. name, pok and "" or values)
end

-- the same through the cookie and JSON body namespaces (the prefix carries a
-- cookie name there)
do
    local pok, values = pcall(bp.json, bp, "request.cookie.json.c[0]", '{"k":"v"}', false)
    ok(pok and values["request.cookie.json.c[0].value:k"] == "v", "cookie-shaped prefix", pok and "" or values)
end

-- ===========================================================================
print("- 4. rules still see the values")
-- ===========================================================================
local SQLI = "1' UNION SELECT password FROM users--"
local Q_ATTACK = "type=poi&facets[]=" .. ngx.escape_uri('{"field":"' .. SQLI .. '"}') .. "&activeFilter[]=%7B%7D"

local function sqli_rule(variable)
    return {
        id = 990001, phase = "access", tags = {},
        conditions = {
            -- `contains`: the harness stubs ngx.re, so rx would never match here
            { variables = { variable }, op = "contains", value = "UNION SELECT", transform = {} },
        },
    }
end

for _, variable in ipairs({ "request.arg.value", "request.query.value",
                            "request.arg.value:facets[]" }) do
    for _, path in ipairs({ "dispatcher", "compiled" }) do
        H.request.raw_query = Q_ATTACK
        H.reset()
        local r = sqli_rule(variable)
        if path == "compiled" then H.attach_resolvers(r) end
        local pok, got = pcall(H.match, r)
        ok(pok and got == true, "SQLi in facets[] caught via " .. variable .. " [" .. path .. "]",
           pok and tostring(got) or got)
    end
end

-- benign production query: no Lua error through the engine resolvers
for i, q in ipairs({ Q1, Q2, Q3 }) do
    H.request.raw_query = q
    H.reset()
    local pok, got = pcall(H.match, sqli_rule("request.arg.value"))
    ok(pok and got == false, "benign query " .. i .. " through the engine", pok and tostring(got) or got)
end
H.request.raw_query = ""

-- ===========================================================================
print("- 5. a Lua error in the flattener fails the parse, never escapes")
-- ===========================================================================
do
    -- force an error from inside flattenTable (keyname:lower())
    local mt = getmetatable("").__index
    local orig = mt.lower
    mt.lower = function(s)
        if type(s) == "string" and s:find("boom", 1, true) then error("injected") end
        return orig(s)
    end
    local pok, values, err = pcall(bp.json, bp, "request.query.json:x", '{"boom":"1"}', false)
    mt.lower = orig
    ok(pok and values == nil and err ~= nil, "json() returns nil, err", pok and tostring(err) or values)

    mt.lower = function(s)
        if type(s) == "string" and s:find("boom", 1, true) then error("injected") end
        return orig(s)
    end
    local pok2, v = pcall(bp.urlencoded, bp, "request.query", "x=%7B%22boom%22:1%7D", false)
    mt.lower = orig
    ok(pok2 and v and v["request.query.value:x"] == '{"boom":1}',
       "nested JSON arg kept as an opaque string", pok2 and "" or v)
end

print(fails == 0 and "ALL OK" or (fails .. " FAILURE(S)"))
os.exit(fails == 0 and 0 or 1)
