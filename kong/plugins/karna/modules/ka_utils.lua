local ngx                   = ngx
local kong                  = kong
local rmatch                = ngx.re.match

local request_get_header            = kong.request.get_header
local request_get_headers           = kong.request.get_headers
local request_get_path_with_query   = kong.request.get_path_with_query
local response_get_headers          = kong.service.response.get_headers
local service_response_get_status   = kong.service.response.get_status
local response_get_status           = kong.response.get_status
local request_get_method            = kong.request.get_method
local request_get_http_version      = kong.request.get_http_version

local string_match                  = string.match

local internal_dev_host     = "karna-test"

local _M = {}

_M.auditlog_path = ""
_M.redis_host = ""
_M.redis_port = 6379
_M.redis_password = nil

--_M.debug = function (i) return end
--_M.inspect = kong.log.inspect
--_M.debug = kong.log.debug

_M.debug       = function(i) return end
_M.inspect     = function(i) return end

_M.dev_env_enabled = function (self)
    -- get host request header
    local host = request_get_header("host")
    if host == internal_dev_host then
        local test_header = request_get_header("x-karna-test")
        if test_header then
            return true
        end
    end
    return false
end

_M.dev_filter_rule_id = function(self, is_dev_env_enabled)
    local filter_rule_id = false
    if is_dev_env_enabled then
        local test_rule_id = kong.request.get_header("x-karna-test-rule-id")
        if test_rule_id then
            filter_rule_id = test_rule_id
        end
    end
    return filter_rule_id
end

_M.urldecode = function(self, s)
    -- try to urldecode 3 times
    for i=1,3 do
        if string.match(s, '%%[a-fA-F0-9][a-fA-F0-9]') then
            s = ngx.unescape_uri(s)
        end
    end

    return s
end

---Attempts to decode a base64 string safely using pcall
---@param self table The module instance
---@param value string The string to attempt base64 decoding on
---@param debug_enabled boolean Whether to log debug information
---@return string|nil decoded The decoded string if successful, nil otherwise
---@return boolean success Whether the decoding was successful
_M.base64_decode = function(self, value, debug_enabled)
    if not value or type(value) ~= "string" then
        return nil, false
    end
    
    -- Replace base64url specific characters to make it compatible
    local prepared_value = value:gsub("+", "-"):gsub("/", "_")
    
    -- Replace URL-encoded equals sign with actual equals sign
    prepared_value = prepared_value:gsub("%%3[dD]", "=")
    
    -- Use pcall to safely handle decoding errors
    local b64 = require "ngx.base64"
    local status, decoded = pcall(b64.decode_base64url, prepared_value)
    
    if status and decoded then
        if debug_enabled then
            self.debug("BASE64 decoded successfully: " .. tostring(decoded))
        end
        return tostring(decoded), true
    else
        if debug_enabled then
            self.debug("BASE64 decode failed for value: " .. value)
        end
        return nil, false
    end
end

_M.request_body_parser_type = function(self)
    local request_body_type = "text"

    -- get request header content-type
    local content_type = request_get_header("content-type")

    if content_type then
        if string.match(content_type, "json") then
            request_body_type = "json"
        end

        if string.match(content_type, "multipart") then
            request_body_type = "multipart"
        end

        if string.match(content_type, "www%-form%-urlencoded") then
            request_body_type = "urlencoded"
        end

        if string.match(content_type, "xml") then
            request_body_type = "xml"
        end
    end

    return request_body_type
end

_M.url_is_in_scope = function (self, url, header_host)
    local url_parsed = self:url_parser(url)
    if header_host == url_parsed.host then
        return true
    end
end

_M.url_parser = function(self, raw_url)
    local url = {
        scheme      = nil,
        host        = nil,
        port        = nil,
        path        = nil,
        query       = nil,
        fragment    = nil
    }

    local m = rmatch(raw_url, "^([a-z0-9-]+)://", "jo")
    if m then url.scheme = m[1] end

    local m = rmatch(raw_url, "^([a-z0-9-]+://)?([a-zA-Z0-9_.:-]+)", "jo")
    if m then
        if string.match(m[2], ":%d+") then
            local host_port = string.match(m[2], "([^:]+):(%d+)")
            url.host = host_port[1]
            url.port = host_port[2]
        else
            url.host = m[2]
        end
    end

    local m = rmatch(raw_url, "^([a-z0-9-]+://)?([a-zA-Z0-9_.:-]+)(/[^?]*)", "jo")
    if m then url.path = m[3] end

    local m = rmatch(raw_url, "^([a-z0-9-]+://)?([a-zA-Z0-9_.:-]+)/[^?]*[?]([^#]+)", "jo")
    if m then url.query = m[3] end

    local m = rmatch(raw_url, "^([a-z0-9-]+://)?([a-zA-Z0-9_.:-]+)/[^?]*([?][^#]+)?[#](.+)", "jo")
    if m then url.fragment = m[4] end

    return url
end

_M.utf8FromHex = function(self, hex)
    local result = ""

    local cleanHex = hex:gsub("%%u", "")

    -- convert hex to integer
    local code = tonumber(cleanHex, 16)

    -- input check
    if not code then
        return result
    end

    if code < 0x80 then
        -- 1 byte (0xxxxxxx)
        result = string.char(code)
    elseif code < 0x800 then
        -- 2 byte (110xxxxx 10xxxxxx)
        result = string.char(
            0xC0 + math.floor(code / 0x40),
            0x80 + (code % 0x40)
        )
    elseif code < 0x10000 then
        -- 3 byte (1110xxxx 10xxxxxx 10xxxxxx)
        result = string.char(
            0xE0 + math.floor(code / 0x1000),
            0x80 + (math.floor(code / 0x40) % 0x40),
            0x80 + (code % 0x40)
        )
    elseif code < 0x110000 then
        -- 4 byte (11110xxx 10xxxxxx 10xxxxxx 10xxxxxx)
        result = string.char(
            0xF0 + math.floor(code / 0x40000),
            0x80 + (math.floor(code / 0x1000) % 0x40),
            0x80 + (math.floor(code / 0x40) % 0x40),
            0x80 + (code % 0x40)
        )
    else
        return result
    end

    return result
end

_M.hexFromUTF8 = function(self, utf8char)
    if not string_match(utf8char, "^[nil]+$") and utf8char ~= "" then
        self.inspect(utf8char)
        local bytes = {utf8char:byte(1, -1)}
        local codepoint = nil

        if #bytes == 1 then
            -- Carattere 1-byte (0xxxxxxx)
            codepoint = bytes[1]
        elseif #bytes == 2 then
            -- Carattere 2-byte (110xxxxx 10xxxxxx)
            codepoint = (bytes[1] - 0xC0) * 0x40 + (bytes[2] - 0x80)
        elseif #bytes == 3 then
            -- Carattere 3-byte (1110xxxx 10xxxxxx 10xxxxxx)
            codepoint = (bytes[1] - 0xE0) * 0x1000 + (bytes[2] - 0x80) * 0x40 + (bytes[3] - 0x80)
        elseif #bytes == 4 then
            -- Carattere 4-byte (11110xxx 10xxxxxx 10xxxxxx 10xxxxxx)
            codepoint = (bytes[1] - 0xF0) * 0x40000 + (bytes[2] - 0x80) * 0x1000 + (bytes[3] - 0x80) * 0x40 + (bytes[4] - 0x80)
        end

        if not codepoint then
            return utf8char
        end

        return string.format("%%u%04x", codepoint)
    else
        return utf8char
    end
end

_M.copy_rule_table = function(self, obj, configured_paranoia_lvel)
    if type(obj) ~= 'table' then return obj end
    local res = {}
    for k, v in pairs(obj) do
        res[self:copy_rule_table(k)] = self:copy_rule_table(v)
    end
    return res
end

_M.get_auditlog = function(self, matched_rule, matched_parts)
    local cjson = require "cjson"

    local service = kong.router.get_service()
    local route = kong.router.get_route()

    local customer = nil
    local hostname = nil

    -- match <customer>_<hostname> from service.name
    if service.name then
        customer = string.match(service.name, "^(.-)_")
        hostname = string.match(service.name, "_(.-)$")
    end

    -- since request headers and response headers need to be flat on logs
    -- we can't use get_headers() directly
    local request_headers = {}
    local response_headers = {}
    for k,v in pairs(request_get_headers()) do
        if type(v) == "table" then
            request_headers[k] = table.concat(v, ", ")
        else
            request_headers[k] = v
        end
    end
    for k,v in pairs(response_get_headers()) do
        if type(v) == "table" then
            response_headers[k] = table.concat(v, ", ")
        else
            response_headers[k] = v
        end
    end

    local json_log = {
        customer = customer,
        ["service-name"] = hostname,
        ["service-id"] = service.id,
        transaction = {
            client_ip = ngx.var.remote_addr,
            time_stamp = os.date("%a %b %d %H:%M:%S %Y"),
            server_id = ngx.var.server_id,
            client_port = ngx.var.remote_port,
            host_ip = ngx.var.server_addr,
            host_port = ngx.var.server_port,
            unique_id = ngx.var.request_id,
            request = {
                method = kong.request.get_method(),
                http_version = kong.request.get_http_version(),
                uri = kong.request.get_path_with_query(),
                headers = request_headers
            },
            response = {
                http_code = kong.response.get_status(),
                headers = response_headers
            },
            producer = {
                modsecurity = "Karna",
                connector = "none",
                secrules_engine = "DetectionOnly",
                components = {
                    "Karna"
                }
            },
            messages = cjson.empty_array
        }
    }

    --json_log.transaction.request.uri = request_uri
    --json_log.transaction.request.headers = request_headers
    --json_log.transaction.response.headers = response_headers

    local matched_parts_string = ""
    if matched_rule and matched_parts then
        for _,v in pairs(matched_parts) do
            if v.matched_on ~= "var:paranoia_level" then
                matched_parts_string = matched_parts_string .. "Matched on: " .. v.matched_on .. " - Matched value: " .. v.matched_value .. " | "
            end
        end

        -- remove last 3 characters from matched_parts_string
        matched_parts_string = string.sub(matched_parts_string, 1, -4)

        local tags = matched_rule.tags or {"karna"}
        local rule_id = matched_rule.id or "0"

        json_log.transaction.messages = {
            {
                message = matched_rule.message,
                details = {
                    ruleId = rule_id,
                    data = matched_parts_string,
                    tags = tags
                }
            }
        }

        --[[json_log.transaction.messages[1].message = matched_rule.message
        json_log.transaction.messages[1].details.ruleId = rule_id
        json_log.transaction.messages[1].details.data = matched_parts_string
        json_log.transaction.messages[1].details.tags = tags]]--
    end

    if matched_rule then
        if matched_rule.response_status_override then
            json_log.transaction.response.http_code = matched_rule.response_status_override
        end
    end

    return json_log
end

-- Normalize sibling-plugin log entries written to
-- kong.ctx.shared.karna.log_entries. Each accepted entry must carry string
-- `source`, `rule_id` and `message`; `tags` (array) and `metadata` (table) are
-- optional and passed through. Oversize strings are clipped. Malformed entries
-- are silently dropped to keep one bad caller from breaking the audit log.
_M.build_external_matches = function(self, raw_entries)
    local cjson = require "cjson"
    if type(raw_entries) ~= "table" or #raw_entries == 0 then
        return cjson.empty_array
    end
    local out = {}
    for _, e in ipairs(raw_entries) do
        if type(e) == "table"
            and type(e.source) == "string"
            and type(e.rule_id) == "string"
            and type(e.message) == "string" then
            local entry = {
                source  = string.sub(e.source, 1, 100),
                rule_id = string.sub(e.rule_id, 1, 100),
                message = string.sub(e.message, 1, 1000),
            }
            if type(e.tags) == "table" then
                entry.tags = e.tags
            end
            if type(e.metadata) == "table" then
                entry.metadata = e.metadata
            end
            out[#out + 1] = entry
        end
    end
    if #out == 0 then
        return cjson.empty_array
    end
    return out
end

_M.get_auditlog_v2 = function(self, matched_rules, plugin_conf)
    local cjson = require "cjson"

    local service = kong.router.get_service()

    -- flatten request headers (tables to comma-separated strings)
    local request_headers = {}
    for k,v in pairs(request_get_headers()) do
        if type(v) == "table" then
            request_headers[k] = table.concat(v, ", ")
        else
            request_headers[k] = v
        end
    end

    -- flatten response headers
    local response_headers = {}
    for k,v in pairs(response_get_headers()) do
        if type(v) == "table" then
            response_headers[k] = table.concat(v, ", ")
        else
            response_headers[k] = v
        end
    end

    -- build matches array
    local matches = cjson.empty_array
    if matched_rules and #matched_rules > 0 then
        matches = {}
        for _, matched in pairs(matched_rules) do
            local rule = matched.rule
            local parts = matched.part

            -- build matched_parts as structured array
            local matched_parts = {}
            if parts then
                for _, p in pairs(parts) do
                    if p.matched_on and p.matched_on ~= "var:paranoia_level" then
                        matched_parts[#matched_parts + 1] = {
                            on = p.matched_on,
                            value = p.matched_value and string.sub(tostring(p.matched_value), 1, 200) or ""
                        }
                    end
                end
            end

            -- determine action label
            local action_label = "log"
            if rule.action and rule.action.fixed_response then
                if plugin_conf.engine_blocking_mode then
                    action_label = "block"
                else
                    action_label = "detect"
                end
            end

            matches[#matches + 1] = {
                rule_id = tostring(rule.id or "0"),
                message = rule.message or "",
                tags = rule.tags or {},
                matched_parts = matched_parts,
                action = action_label
            }
        end
    end

    -- upstream latency: prefer header set by upstream/sibling plugins (ms),
    -- fallback to nginx upstream timer ($upstream_response_time, seconds float).
    local latency_ms = tonumber(response_headers["x-karna-upstream-latency"])
    if not latency_ms then
        local urt = ngx.var.upstream_response_time
        if urt then
            local first = tostring(urt):match("^[^,]+")
            local secs = tonumber(first)
            if secs then latency_ms = secs * 1000 end
        end
    end
    latency_ms = latency_ms or 0

    -- collect sibling-plugin log entries (external_matches), if any
    local raw_external = nil
    if kong.ctx.shared.karna and kong.ctx.shared.karna.log_entries then
        raw_external = kong.ctx.shared.karna.log_entries
    end
    local external_matches = self:build_external_matches(raw_external)

    local json_log = {
        version = "2.0",
        timestamp = os.date("!%Y-%m-%dT%H:%M:%S", os.time()) .. "." .. string.format("%03d", (ngx.now() % 1) * 1000) .. "Z",
        request_id = ngx.var.request_id,
        service = {
            id = service.id,
            name = service.name
        },
        client = {
            ip = ngx.var.remote_addr,
            port = tonumber(ngx.var.remote_port) or 0
        },
        server = {
            ip = ngx.var.server_addr,
            port = tonumber(ngx.var.server_port) or 0
        },
        request = {
            method = kong.request.get_method(),
            uri = kong.request.get_path_with_query(),
            http_version = tostring(kong.request.get_http_version()),
            headers = request_headers
        },
        response = {
            status = kong.response.get_status(),
            headers = response_headers,
            latency_ms = latency_ms
        },
        engine = {
            mode = plugin_conf.engine_blocking_mode and "blocking" or "detection",
            paranoia_level = tonumber(plugin_conf.paranoia_level) or 1
        },
        matches = matches,
        external_matches = external_matches
    }

    return json_log
end

_M.write_auditlog = function(premature, json_log, auditlog_path, timestamp, request_id)
    if premature then return end

    local cjson = require "cjson"

    -- write a file log
    local filename = auditlog_path.."/"..timestamp.."-ka-auditlog-"..request_id..".json"
    kong.log.debug("Karna: writing audit log to file: ", filename)
    local file = io.open(filename, "w")
    if file then
        local json_log_no_newlines = cjson.encode(json_log):gsub("[\r\n]","")
        file:write(json_log_no_newlines)
        file:close()
    else
        kong.log.err("Karna: failed to write audit log to file: ", filename)
    end
end

_M.redis_connect = function(self)
    local redis_client = require "resty.redis"
    local red = redis_client:new()

    if not red then
        kong.log.err("Karna: failed to connect to Redis")
    end

    red:set_timeouts(1000, 1000, 1000)

    local ok, err = red:connect(self.redis_host, self.redis_port)
    if not ok then
        kong.log.err("Karna: failed to connect to Redis " .. err)
    end

    if self.redis_password then
        local auth_ok, err = red:auth(self.redis_password)
        if not auth_ok then
            kong.log.err("Karna: failed to authenticate to Redis: ", err)
            return
        end
    end

    return red
end

_M.redis_incr_key = function(self, key, expire_time)
    local redis_client = self:redis_connect()

    if redis_client then
        -- check if key exists
        local exists, err = redis_client:get(key)

        local res, err = redis_client:incr(key)
        if not res then
            kong.log.err("Karna: failed to increment key: ", err)
            return
        end

        if exists == ngx.null then
            if expire_time then
                local ok, err = redis_client:expire(key, expire_time)
                if not ok then
                    kong.log.err("Karna: failed to set expire time for key: ", err)
                    return
                end
            end
        end
    end
end

_M.redis_incr_key_async = function(premature, self, plugin_conf, key, expire_time)
    if not premature then
        self.redis_host = plugin_conf.redis_host
        self.redis_port = plugin_conf.redis_port
        self.redis_password = plugin_conf.redis_password

        local redis_client = self:redis_connect()

        if redis_client then
            -- check if key exists
            local exists, err = redis_client:get(key)

            local res, err = redis_client:incr(key)
            if not res then
                kong.log.err("Karna: failed to increment key: ", err)
                return
            end

            if exists == ngx.null then
                if expire_time then
                    local ok, err = redis_client:expire(key, expire_time)
                    if not ok then
                        kong.log.err("Karna: failed to set expire time for key: ", err)
                        return
                    end
                end
            end
        end
    end
end

return _M
