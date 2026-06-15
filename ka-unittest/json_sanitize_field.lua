-- ka-unittest/json_sanitize_field.lua
--
-- Unit-test the per-field JSON sanitisation used by the `fix_matched_parts`
-- action (the "sanitize-not-block" primitive). When a sanitize rule matches a
-- value inside a JSON body, Karna must clean ONLY that field's value and leave
-- the rest of the document — structure and the other, legitimate fields —
-- intact. The previous code raw-stripped the whole JSON body, deleting every
-- `"` and unconditionally removing `%` / `\`, which corrupted unrelated fields
-- and produced malformed JSON for the upstream (reported by BackBox AI,
-- https://backbox.dev).
--
-- We replicate the path-walk + clean logic inline (cjson isn't available in the
-- plain CI Lua sandbox, and the risk lives entirely in resolving the flattened
-- key path against the decoded table — the decode/encode themselves are
-- cjson's job). KEEP IN SYNC with kong/plugins/karna/modules/ka_engine.lua →
-- _M.__fix_matching_parts (the _ue_clean / _json_clean_field helpers).
--
-- Run from repo root:
--   lua ka-unittest/json_sanitize_field.lua

local string_gsub, string_gmatch = string.gsub, string.gmatch

-- Mirror of the engine's _ue_clean + _json_clean_field (operating on a decoded
-- table, exactly as the real code does after cjson_safe.decode).
local function make_cleaner(remove_pattern)
    local function _ue_clean(s)
        if type(s) ~= "string" then return s end
        s = string_gsub(s, "%%", "")
        s = string_gsub(s, "\\", "")
        return (string_gsub(s, remove_pattern, ""))
    end
    return function(json_body, path)
        if type(json_body) ~= "table" then return false end
        local function clean_leaf(node, key)
            if type(node[key]) == "string" then
                node[key] = _ue_clean(node[key])
                return true
            end
            return false
        end
        if json_body[path] ~= nil and clean_leaf(json_body, path) then return true end
        local segs = {}
        for s in string_gmatch(path, "[^.]+") do segs[#segs + 1] = s end
        if #segs == 0 then return false end
        local node = json_body
        for i = 1, #segs - 1 do
            local nxt = node[segs[i]]
            if nxt == nil then
                local nk = tonumber(segs[i])
                if nk ~= nil then nxt = node[nk] end
            end
            if type(nxt) ~= "table" then return false end
            node = nxt
        end
        local leaf = segs[#segs]
        if node[leaf] ~= nil then return clean_leaf(node, leaf) end
        local n = tonumber(leaf)
        if n ~= nil and node[n] ~= nil then return clean_leaf(node, n) end
        return false
    end
end

local clean = make_cleaner('["\']')
local pass, fail = 0, 0
local function eq(got, want, msg)
    if got == want then
        pass = pass + 1
        print("  ok  - " .. msg)
    else
        fail = fail + 1
        print("  FAIL- " .. msg .. "  got=" .. tostring(got) .. " want=" .. tostring(want))
    end
end

-- 1) top-level: only the matched field is cleaned; siblings (including a value
--    that legitimately contains % and \) are left exactly as-is.
local t1 = { q = "x'y\"z", keep = "50% off \\ ok", note = "a;b;c" }
eq(clean(t1, "q"), true, "top-level matched field returns true")
eq(t1.q, "xyz", "matched field cleaned")
eq(t1.keep, "50% off \\ ok", "sibling with % and \\ left untouched")
eq(t1.note, "a;b;c", "other sibling untouched")

-- 2) nested object field via dotted path
local t2 = { user = { name = "o'brien", id = "42" } }
eq(clean(t2, "user.name"), true, "nested field returns true")
eq(t2.user.name, "obrien", "nested field cleaned")
eq(t2.user.id, "42", "nested sibling untouched")

-- 3) array element (cjson decodes JSON arrays to 1-indexed Lua tables)
local t3 = { items = { "a'x", "b'y" } }
eq(clean(t3, "items.1"), true, "array element returns true")
eq(t3.items[1], "ax", "array element cleaned")
eq(t3.items[2], "b'y", "array sibling untouched")

-- 4) unresolvable paths return false so the caller falls back to the raw-strip
--    (the attack is still neutralised, just not per-field)
eq(clean({ x = "y" }, "missing"), false, "missing key -> false (fallback)")
eq(clean({ a = { b = 1 } }, "a.b.c"), false, "over-deep path -> false (fallback)")

-- 5) a top-level key that itself contains dots (whole-path-as-key branch)
local t5 = { ["a.b"] = "z'z" }
eq(clean(t5, "a.b"), true, "dotted top-level key returns true")
eq(t5["a.b"], "zz", "dotted top-level key cleaned")

-- 6) non-string leaf (number / object) -> false (fallback, never coerces)
eq(clean({ n = 5 }, "n"), false, "numeric leaf -> false (fallback)")

print(string.format("\n%d passed, %d failed", pass, fail))
os.exit(fail == 0 and 0 or 1)
