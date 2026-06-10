package = "kong-plugin-karna"

version = "1.1.2-0"

local pluginName = package:match("^kong%-plugin%-(.+)$")

supported_platforms = {"linux"}
source = {
  url = "git+https://github.com/sicuranext/karna.git",
  tag = "v1.1.2"
}

description = {
  summary = "Karna — OWASP CRS-compatible WAF engine for Kong Gateway",
  homepage = "https://github.com/sicuranext/karna",
  license = "Elastic-2.0"
}

dependencies = {
  "lua >= 5.1",
  "lua-zlib",
}

build = {
  type = "builtin",
  modules = {
    ["kong.plugins."..pluginName..".handler"]         = "kong/plugins/"..pluginName.."/handler.lua",
    ["kong.plugins."..pluginName..".schema"]          = "kong/plugins/"..pluginName.."/schema.lua",
    ["kong.plugins."..pluginName..".version"]         = "kong/plugins/"..pluginName.."/version.lua",
    ["kong.plugins."..pluginName..".ka_engine"]       = "kong/plugins/"..pluginName.."/modules/ka_engine.lua",
    ["kong.plugins."..pluginName..".ka_body_parser"]  = "kong/plugins/"..pluginName.."/modules/ka_body_parser.lua",
    ["kong.plugins."..pluginName..".ka_multipart"]    = "kong/plugins/"..pluginName.."/modules/ka_multipart.lua",
    ["kong.plugins."..pluginName..".ka_utils"]        = "kong/plugins/"..pluginName.."/modules/ka_utils.lua",
    ["kong.plugins."..pluginName..".ka_seclang"]      = "kong/plugins/"..pluginName.."/modules/seclang.lua",
    ["kong.plugins."..pluginName..".ka_mcp"]          = "kong/plugins/"..pluginName.."/modules/ka_mcp.lua",
    ["kong.plugins."..pluginName..".ka_mcp_sse"]      = "kong/plugins/"..pluginName.."/modules/ka_mcp_sse.lua",
    ["kong.plugins."..pluginName..".ka_compile"]      = "kong/plugins/"..pluginName.."/modules/ka_compile.lua",
    ["kong.plugins."..pluginName..".ka_re2"]          = "kong/plugins/"..pluginName.."/modules/ka_re2.lua",
    ["kong.plugins."..pluginName..".ka_re2_gate"]     = "kong/plugins/"..pluginName.."/modules/ka_re2_gate.lua",
    ["kong.plugins."..pluginName..".ka_ac"]           = "kong/plugins/"..pluginName.."/modules/ka_ac.lua",

    ["kong.plugins."..pluginName..".libinjection"]    = "kong/plugins/"..pluginName.."/modules/libinjection.lua",
    ["kong.plugins."..pluginName..".slaxml"]          = "kong/plugins/"..pluginName.."/modules/slaxml.lua",

    ["kong.plugins."..pluginName..".ka_rules_crs_fix"]  = "kong/plugins/"..pluginName.."/rules/coreruleset_fix.lua",
  }
}
