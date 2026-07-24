local lfs = require "lfs"

local kong = kong
local sort = table.sort

local DEFAULT_PLUGINS_PATH = "/opt/coreruleset-plugins/"
local PLUGIN_NAME_PATTERN = "^[A-Za-z0-9][A-Za-z0-9._-]*$"


local function normalized_root(path)
  if type(path) ~= "string" or path == "" or path:find("\0", 1, true) then
    return DEFAULT_PLUGINS_PATH
  end
  if path:sub(-1) ~= "/" then
    return path .. "/"
  end
  return path
end


local function directory_entries(path)
  local ok, iterator, state = pcall(lfs.dir, path)
  if not ok or not iterator then
    return {}
  end

  local entries = {}
  for entry in iterator, state do
    if entry ~= "." and entry ~= ".." then
      entries[#entries + 1] = entry
    end
  end
  return entries
end


local function is_real_directory(path)
  -- Do not follow symlinked plugin directories. An inventory endpoint should
  -- describe the configured plugin root, not become a filesystem explorer.
  if lfs.symlinkattributes(path, "mode") == "link" then
    return false
  end
  return lfs.attributes(path, "mode") == "directory"
end


local function plugin_inventory(root)
  local plugins = {}

  for _, name in ipairs(directory_entries(root)) do
    if name:match(PLUGIN_NAME_PATTERN) and name ~= "." and name ~= ".." then
      local package_path = root .. name
      local conf_path = package_path .. "/plugins"
      if is_real_directory(package_path) and is_real_directory(conf_path) then
        local conf_files = {}
        for _, filename in ipairs(directory_entries(conf_path)) do
          local full_path = conf_path .. "/" .. filename
          if filename:match("%.conf$")
             and lfs.symlinkattributes(full_path, "mode") ~= "link"
             and lfs.attributes(full_path, "mode") == "file" then
            conf_files[#conf_files + 1] = filename
          end
        end
        sort(conf_files)
        if #conf_files > 0 then
          plugins[#plugins + 1] = {
            name = name,
            config_files = conf_files,
            config_file_count = #conf_files,
          }
        end
      end
    end
  end

  sort(plugins, function(a, b) return a.name < b.name end)
  return plugins
end


return {
  ["/karna/crs-plugins/:plugin_id"] = {
    resource = "karna-crs-plugins",

    GET = function(self)
      local plugin, err = kong.db.plugins:select({ id = self.params.plugin_id })
      if err then
        return kong.response.exit(500, { message = "Could not read plugin configuration" })
      end
      if not plugin or plugin.name ~= "karna" then
        return kong.response.exit(404, { message = "Karna plugin not found" })
      end

      local root = normalized_root(plugin.config and plugin.config.crs_plugins_path)
      return kong.response.exit(200, {
        plugin_id = plugin.id,
        path = root,
        plugins = plugin_inventory(root),
      })
    end,
  },
}
