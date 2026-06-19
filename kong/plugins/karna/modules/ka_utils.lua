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

local ka_version            = require "kong.plugins.karna.version"

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
        -- HTTP content-type is case-insensitive: lowercase before matching so
        -- e.g. "application/JSON" or "APPLICATION/X-WWW-FORM-URLENCODED" parse
        -- as their real type instead of falling through to raw "text" (which
        -- let structured-arg attacks skip inspection — WAF bypass).
        content_type = content_type:lower()

        -- Classify on the BASE media type only — the token before the first
        -- `;` or whitespace — NOT a substring of the whole header. Substring
        -- matching on the full value let a parser keyword smuggled into a
        -- parameter reclassify the body: with sequential `if` blocks the LAST
        -- match won, so `application/json;charset=myxml` matched "json" and
        -- then "xml" (inside "myxml") and was XML-parsed. The XML parser
        -- choked on the JSON body while the backend read base type
        -- `application/json` and parsed it as JSON — a parser desync that
        -- skipped argument inspection (body-parser bypass). Extracting the
        -- base type mirrors check_request_content_type_enforce, and `elseif`
        -- removes the "last match wins" footgun. Permissive structured
        -- subtype suffixes (`+json`, `+xml`) are still honoured so
        -- application/cloudevents+json, application/soap+xml et al. classify
        -- correctly.
        local base = string.match(content_type, "^%s*([^;%s]+)")
        if base then
            if base == "application/json" or string.match(base, "%+json$") then
                request_body_type = "json"
            elseif base == "text/xml" or base == "application/xml"
                   or string.match(base, "%+xml$") then
                request_body_type = "xml"
            elseif base == "application/x-www-form-urlencoded" then
                request_body_type = "urlencoded"
            elseif string.match(base, "^multipart/") then
                request_body_type = "multipart"
            end
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

-- Build the request enrichment block for audit log v2. Reads brand-neutral
-- well-known keys from kong.ctx.shared.* (set by sibling plugins) and a
-- free-form bucket from kong.ctx.shared.karna.enrichment for non-standard
-- fields. Returns nil if no enrichment data is present, so the caller can
-- omit the field entirely from the JSON output.
--
-- `shared` is the kong.ctx.shared table; passed in explicitly so the function
-- stays testable without an ngx/kong global.
_M.build_enrichment_block = function(self, shared)
    if type(shared) ~= "table" then return nil end

    local block = {}
    local has_any = false

    -- geoip
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

    -- asn
    if shared.asn_id or shared.asn_org then
        local asn = {}
        if shared.asn_id  then asn.id  = tostring(shared.asn_id)  end
        if shared.asn_org then asn.org = tostring(shared.asn_org) end
        block.asn = asn
        has_any = true
    end

    -- useragent: pass through unchanged when a table, skip otherwise
    if type(shared.useragent) == "table" then
        block.useragent = shared.useragent
        has_any = true
    end

    -- free-form custom bucket
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
            -- precedence: sanitized > rate_limited > block > detect > log
            -- - sanitized: rule had fix_matched_parts and the engine
            --   stripped dangerous chars before forwarding upstream
            --   (Karna's FP-mitigation primitive — request still goes
            --   through, just neutralized)
            -- - rate_limited: rule had rate_limit and the Redis counter
            --   exceeded the configured limit (returned 429)
            -- - block: blocking mode + fixed_response → 403 returned
            -- - detect: monitoring mode + fixed_response → 200 logged
            -- - log: rule fired without a response action (pass / setvar
            --   / under-threshold rate_limit increment)
            local action_label = "log"
            if matched.sanitized then
                action_label = "sanitized"
            elseif matched.rate_limited then
                action_label = "rate_limited"
            elseif rule.action and rule.action.fixed_response then
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

    -- request-level latency breakdown (ms), read from the nginx timers in the
    -- log phase — no extra instrumentation in the earlier phases:
    --   total    = the whole request          ($request_time)
    --   upstream = time waiting for upstream   (latency_ms, computed above)
    --   kong     = the gateway's own processing (Karna + other plugins + proxy)
    --              i.e. total minus upstream, clamped at zero
    local total_ms
    local rt = tonumber(tostring(ngx.var.request_time or ""):match("^[^,]+"))
    if rt then total_ms = rt * 1000 end
    local kong_ms
    if total_ms then
        kong_ms = total_ms - latency_ms
        if kong_ms < 0 then kong_ms = 0 end
    end
    local function _round2(n) return n and tonumber(string.format("%.2f", n)) or 0 end
    local latencies = {
        total = _round2(total_ms),
        upstream = _round2(latency_ms),
        kong = _round2(kong_ms)
    }

    -- collect sibling-plugin log entries (external_matches), if any
    local raw_external = nil
    if kong.ctx.shared.karna and kong.ctx.shared.karna.log_entries then
        raw_external = kong.ctx.shared.karna.log_entries
    end
    local external_matches = self:build_external_matches(raw_external)

    -- collect request enrichment (geoip / asn / useragent / custom), if any
    local enrichment = self:build_enrichment_block(kong.ctx.shared)

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
            latency_ms = latency_ms,
            latencies = latencies
        },
        engine = {
            name = "karna",
            version = ka_version.version,
            commit = ka_version.commit,
            mode = plugin_conf.engine_blocking_mode and "blocking" or "detection",
            paranoia_level = tonumber(plugin_conf.paranoia_level) or 1
        },
        matches = matches,
        external_matches = external_matches
    }

    if enrichment then
        json_log.enrichment = enrichment
    end

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

-- Increment a Redis counter (atomically via INCR) and, if the key
-- was newly created by this call, set its TTL to `expire_time`
-- seconds — fixed-window rate-limit semantics. Returns the new
-- counter value on success, or nil if Redis is unreachable / the
-- INCR failed; callers (notably the `rate_limit` rule action) treat
-- nil as "counter unavailable, fail open".
_M.redis_incr_key = function(self, key, expire_time)
    local redis_client = self:redis_connect()
    if not redis_client then return nil end

    local exists, _err_get = redis_client:get(key)

    local res, err = redis_client:incr(key)
    if not res then
        kong.log.err("Karna: failed to increment key: ", err)
        return nil
    end

    if exists == ngx.null and expire_time then
        local ok, expire_err = redis_client:expire(key, expire_time)
        if not ok then
            kong.log.err("Karna: failed to set expire time for key: ", expire_err)
        end
    end

    return tonumber(res)
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

-- Read-only Redis command whitelist for rule inspection. Deny by default:
-- anything not listed is rejected before it reaches Redis, so a rule can never
-- mutate state or run an admin / blocking / keyspace-scan command.
local REDIS_INSPECT_READ_CMDS = {
    get = true, strlen = true, exists = true, ttl = true, pttl = true,
    type = true, sismember = true, smismember = true, scard = true,
    hget = true, hexists = true, hlen = true, hstrlen = true,
    llen = true, lindex = true, zscore = true, zrank = true, zcard = true,
}

-- Run a single read-only Redis command for rule inspection. `conf` carries the
-- per-request connection settings (host/port/password/database/timeout/keepalive)
-- so we never mutate shared module state across concurrent requests on a worker.
-- Returns:
--   value, nil   on success (value may be `ngx.null` when the key/member is absent)
--   nil, err     on a disallowed command, connection/auth/select failure, or Redis error
-- The caller (engine) decides the on_error posture (skip / fail_open / fail_closed).
_M.redis_inspect_read = function(self, conf, cmd, ...)
    if not REDIS_INSPECT_READ_CMDS[cmd] then
        return nil, "redis command not allowed for inspection: " .. tostring(cmd)
    end

    local redis_client = require "resty.redis"
    local red = redis_client:new()
    if not red then return nil, "redis: client init failed" end
    if type(red[cmd]) ~= "function" then
        return nil, "redis command unsupported by client: " .. tostring(cmd)
    end

    local t = tonumber(conf and conf.timeout_ms) or 50
    red:set_timeouts(t, t, t)

    local ok, err = red:connect(conf and conf.host or "localhost",
                                conf and conf.port or 6379)
    if not ok then return nil, "redis connect: " .. tostring(err) end

    if conf and conf.password and conf.password ~= "" then
        local auth_ok, aerr = red:auth(conf.password)
        if not auth_ok then
            pcall(function() red:close() end)
            return nil, "redis auth: " .. tostring(aerr)
        end
    end

    local db = tonumber(conf and conf.database) or 0
    if db > 0 then
        local sel_ok, serr = red:select(db)
        if not sel_ok then
            pcall(function() red:close() end)
            return nil, "redis select: " .. tostring(serr)
        end
    end

    local res, cerr = red[cmd](red, ...)
    if res == nil then
        -- network / protocol error: do not pool a possibly-broken connection
        pcall(function() red:close() end)
        return nil, cerr or "redis command failed"
    end

    -- Success (res may be ngx.null for an absent key/member): return the
    -- connection to the per-worker pool. A fresh TCP + auth handshake per
    -- request would be unacceptable on the hot path.
    local pool = tonumber(conf and conf.keepalive_pool_size) or 64
    local idle = tonumber(conf and conf.keepalive_idle_ms) or 60000
    if not red:set_keepalive(idle, pool) then
        pcall(function() red:close() end)
    end

    return res, nil
end

-- Write commands Karna may issue as a rule ACTION side effect (auto-ban /
-- distributed denylist). Separate from the read whitelist; never reachable
-- from the read-inspection path.
local REDIS_WRITE_CMDS = { set = true, sadd = true, srem = true, del = true, expire = true }

-- Run a single write command, fire-and-forget. `conf` carries the per-request
-- connection settings. Usage:
--   redis_write(conf, "set",  key, value, ttl) -> SET key value [EX ttl]
--   redis_write(conf, "sadd", key, member, ttl)-> SADD key member; EXPIRE key ttl (if ttl)
--   redis_write(conf, "srem", key, member)     -> SREM key member
--   redis_write(conf, "del",  key)             -> DEL key
-- Fail-soft: a disallowed command / connection / Redis error is logged and
-- returns nil; it never propagates to block the request.
_M.redis_write = function(self, conf, op, key, arg, ttl)
    if not REDIS_WRITE_CMDS[op] then
        kong.log.err("Karna: redis write command not allowed: ", tostring(op))
        return nil
    end
    local redis_client = require "resty.redis"
    local red = redis_client:new()
    if not red then return nil end

    local t = tonumber(conf and conf.timeout_ms) or 50
    red:set_timeouts(t, t, t)

    local ok, err = red:connect(conf and conf.host or "localhost", conf and conf.port or 6379)
    if not ok then kong.log.err("Karna: redis connect (write): ", tostring(err)); return nil end

    if conf and conf.password and conf.password ~= "" then
        local aok, aerr = red:auth(conf.password)
        if not aok then
            pcall(function() red:close() end)
            kong.log.err("Karna: redis auth (write): ", tostring(aerr)); return nil
        end
    end

    local db = tonumber(conf and conf.database) or 0
    if db > 0 then red:select(db) end

    ttl = tonumber(ttl)
    local res, cerr
    if op == "set" then
        if ttl and ttl > 0 then res, cerr = red:set(key, arg, "EX", ttl)
        else res, cerr = red:set(key, arg) end
    elseif op == "sadd" then
        res, cerr = red:sadd(key, arg)
        if res and ttl and ttl > 0 then red:expire(key, ttl) end
    elseif op == "srem" then
        res, cerr = red:srem(key, arg)
    elseif op == "del" then
        res, cerr = red:del(key)
    elseif op == "expire" then
        res, cerr = red:expire(key, ttl or 0)
    end

    if res == nil then
        pcall(function() red:close() end)
        kong.log.err("Karna: redis " .. op .. " failed: ", tostring(cerr))
        return nil
    end

    local pool = tonumber(conf and conf.keepalive_pool_size) or 64
    local idle = tonumber(conf and conf.keepalive_idle_ms) or 60000
    if not red:set_keepalive(idle, pool) then pcall(function() red:close() end) end
    return res
end

-- Async wrapper for ngx.timer.at in non-access phases (cosocket unavailable inline).
_M.redis_write_async = function(premature, self, conf, op, key, arg, ttl)
    if premature then return end
    self:redis_write(conf, op, key, arg, ttl)
end

return _M
