-- enrichment_block.lua
-- Unit tests for ka_utils.build_enrichment_block — the function that
-- assembles the audit log v2 `enrichment` field from well-known
-- kong.ctx.shared keys and the free-form karna.enrichment bucket.
--
-- The function is replicated inline here to keep the test free of
-- ngx/kong globals. Keep this copy in sync with the source of truth at
-- kong/plugins/karna/modules/ka_utils.lua → _M.build_enrichment_block.

local lu = require("luaunit")

local function build_enrichment_block(shared)
    if type(shared) ~= "table" then return nil end

    local block = {}
    local has_any = false

    if shared.geoip_country_code or shared.geoip_country_name
       or shared.geoip_continent_code or shared.geoip_continent_name then
        local geoip = {}
        if shared.geoip_country_code   then geoip.country_code   = tostring(shared.geoip_country_code)   end
        if shared.geoip_country_name   then geoip.country_name   = tostring(shared.geoip_country_name)   end
        if shared.geoip_continent_code then geoip.continent_code = tostring(shared.geoip_continent_code) end
        if shared.geoip_continent_name then geoip.continent_name = tostring(shared.geoip_continent_name) end
        block.geoip = geoip
        has_any = true
    end

    if shared.asn_id or shared.asn_org then
        local asn = {}
        if shared.asn_id  then asn.id  = tostring(shared.asn_id)  end
        if shared.asn_org then asn.org = tostring(shared.asn_org) end
        block.asn = asn
        has_any = true
    end

    if type(shared.useragent) == "table" then
        block.useragent = shared.useragent
        has_any = true
    end

    if type(shared.karna) == "table" and type(shared.karna.enrichment) == "table" then
        local n = 0
        for _ in pairs(shared.karna.enrichment) do n = n + 1; break end
        if n > 0 then
            block.custom = shared.karna.enrichment
            has_any = true
        end
    end

    if not has_any then return nil end
    return block
end

TestEnrichmentBlock = {}

function TestEnrichmentBlock:test_nil_input_returns_nil()
    lu.assertNil(build_enrichment_block(nil))
end

function TestEnrichmentBlock:test_non_table_input_returns_nil()
    lu.assertNil(build_enrichment_block("string"))
    lu.assertNil(build_enrichment_block(42))
end

function TestEnrichmentBlock:test_empty_shared_returns_nil()
    lu.assertNil(build_enrichment_block({}))
end

function TestEnrichmentBlock:test_only_geoip_country_code()
    local r = build_enrichment_block({ geoip_country_code = "IT" })
    lu.assertEquals(r.geoip.country_code, "IT")
    lu.assertNil(r.geoip.country_name)
    lu.assertNil(r.asn)
    lu.assertNil(r.useragent)
    lu.assertNil(r.custom)
end

function TestEnrichmentBlock:test_full_geoip()
    local r = build_enrichment_block({
        geoip_country_code   = "IT",
        geoip_country_name   = "Italy",
        geoip_continent_code = "EU",
        geoip_continent_name = "Europe",
    })
    lu.assertEquals(r.geoip, {
        country_code   = "IT",
        country_name   = "Italy",
        continent_code = "EU",
        continent_name = "Europe",
    })
end

function TestEnrichmentBlock:test_asn_only()
    local r = build_enrichment_block({ asn_id = "12345", asn_org = "Example ISP" })
    lu.assertEquals(r.asn, { id = "12345", org = "Example ISP" })
    lu.assertNil(r.geoip)
end

function TestEnrichmentBlock:test_useragent_passthrough()
    local ua = { name = "Chrome", version = "131.0", os = "macOS" }
    local r = build_enrichment_block({ useragent = ua })
    lu.assertEquals(r.useragent, ua)
end

function TestEnrichmentBlock:test_useragent_not_a_table_skipped()
    local r = build_enrichment_block({ useragent = "Chrome/131.0" })
    lu.assertNil(r)
end

function TestEnrichmentBlock:test_custom_bucket()
    local r = build_enrichment_block({
        karna = {
            enrichment = { fp_visitor_id = "abc123", tor = true }
        }
    })
    lu.assertEquals(r.custom, { fp_visitor_id = "abc123", tor = true })
end

function TestEnrichmentBlock:test_custom_bucket_empty_skipped()
    local r = build_enrichment_block({ karna = { enrichment = {} } })
    lu.assertNil(r)
end

function TestEnrichmentBlock:test_custom_bucket_not_a_table_skipped()
    local r = build_enrichment_block({ karna = { enrichment = "string" } })
    lu.assertNil(r)
end

function TestEnrichmentBlock:test_all_combined()
    local r = build_enrichment_block({
        geoip_country_code = "DE",
        asn_id             = "1",
        useragent          = { name = "Firefox" },
        karna              = { enrichment = { x = 1 } },
    })
    lu.assertEquals(r.geoip.country_code, "DE")
    lu.assertEquals(r.asn.id, "1")
    lu.assertEquals(r.useragent.name, "Firefox")
    lu.assertEquals(r.custom.x, 1)
end

function TestEnrichmentBlock:test_non_string_values_coerced()
    local r = build_enrichment_block({ geoip_country_code = 42, asn_id = 12345 })
    lu.assertEquals(r.geoip.country_code, "42")
    lu.assertEquals(r.asn.id, "12345")
end

function TestEnrichmentBlock:test_falsy_zero_treated_as_present()
    -- Lua: 0 and "" are truthy, only nil/false are falsy.
    local r = build_enrichment_block({ geoip_country_code = "" })
    lu.assertEquals(r.geoip.country_code, "")
end

function TestEnrichmentBlock:test_explicit_false_treated_as_absent()
    -- Sibling plugins commonly initialise enrichment keys to `false` when
    -- the underlying lookup hasn't run or didn't match. That pattern must
    -- NOT yield an empty block in the audit log.
    local r = build_enrichment_block({
        geoip_country_code   = false,
        geoip_country_name   = false,
        geoip_continent_code = false,
        geoip_continent_name = false,
        asn_id  = false,
        asn_org = false,
    })
    lu.assertNil(r)
end

os.exit(lu.LuaUnit.run())
