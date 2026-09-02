-- ka_tls.lua
--
-- TLS telemetry and pseudonymous connection id, for the audit log (`tls` and
-- `network.connection_id` blocks, both formats) and for the rule variables
-- `tls.*` / `connection.id`. One point of normalisation: audit v1, audit v2
-- and the engine all read the block this module builds once per request.
--
-- Everything comes from nginx variables readable in the HTTP phases; there is
-- no ClientHello hook (Kong owns ssl_client_hello_by_lua and runs no plugin
-- there). $ssl_ciphers and $ssl_curves are the lists the client OFFERED, in
-- the client's order, unknown entries rendered as 0xNNNN by nginx — that is
-- ClientHello material nginx extracts for us. $ssl_curves is empty on a
-- resumed TLS 1.2 session (documented nginx behaviour); TLS 1.3 resumption
-- keeps it.
--
-- connection_id: HMAC-SHA256 over "kc1|<per-worker nonce>|<worker id>|<nginx
-- connection serial>", truncated to 128 bits, hex, prefixed "kc1_". The nginx
-- serial ($connection) is identical for every request on a TCP connection —
-- HTTP/1.1 keepalive and every HTTP/2 stream alike (measured) — and unique
-- instance-wide, but restarts at every start: the nonce makes ids from two
-- instance lifetimes unrelated. The key comes from KARNA_CONNECTION_ID_HMAC_KEY
-- (>= 16 bytes), else a random per-worker key with one warning. No IP, port,
-- session id or other client material enters the digest, and the input is
-- never logged.
--
-- Fail-open by construction: the handler pcall's populate(); a failure leaves
-- the fields absent and never touches the request.

local string_sub    = string.sub
local string_format = string.format
local string_gsub   = string.gsub
local string_byte   = string.byte
local tostring      = tostring
local type          = type

local _M = {}

_M.MAX_LIST_LEN   = 4096      -- byte cap on client_ciphers / client_curves
_M.CACHE_SIZE     = 4096      -- connection serial -> id, per worker
_M.MIN_KEY_LEN    = 16
_M.ID_PREFIX      = "kc1_"
_M.ENV_KEY_NAME   = "KARNA_CONNECTION_ID_HMAC_KEY"

-- karna-tls-v1 fingerprint (see fingerprint_canonical below for the spec).
_M.FP_VERSION     = "karna-tls-v1"
_M.FP_ALGORITHM   = "sha256"
_M.FP_CACHE_SIZE  = 1024

_M.STATUS_NOT_TLS  = "not_tls"
_M.STATUS_COMPLETE = "complete"
_M.STATUS_PARTIAL  = "partial"
_M.STATUS_ERROR    = "error"

-- Field names exposed on the audit `tls` block and as `tls.<name>` variables
-- (besides `enabled` and `capture_status`, which are always present).
_M.FIELDS = { "protocol", "cipher", "curve", "alpn", "sni",
              "session_reused", "early_data", "client_ciphers", "client_curves" }

-- kong.ctx.plugin when running inside Kong, nil elsewhere (unit tests pass
-- their own ctx) — never index a missing global.
local function plugin_ctx()
    if kong and kong.ctx then return kong.ctx.plugin end
    return nil
end

local function to_hex(raw)
    return (string_gsub(raw, ".", function(c)
        return string_format("%02x", string_byte(c))
    end))
end
_M._to_hex = to_hex

------------------------------------------------------------------------------
-- Negotiated telemetry
------------------------------------------------------------------------------

-- Build the normalised TLS block from a variable table (ngx.var, or any table
-- with the same field names). Pure.
function _M.collect(var, max_list_len)
    max_list_len = max_list_len or _M.MAX_LIST_LEN
    if type(var) ~= "table" and type(var) ~= "userdata" then
        return { enabled = false, capture_status = _M.STATUS_ERROR }
    end

    local function get(name)
        local v = var[name]
        if type(v) == "string" then return v end
        return ""
    end

    local protocol = get("ssl_protocol")
    if protocol == "" then
        return { enabled = false, capture_status = _M.STATUS_NOT_TLS }
    end

    local client_ciphers = get("ssl_ciphers")
    local client_curves  = get("ssl_curves")
    if #client_ciphers > max_list_len then client_ciphers = string_sub(client_ciphers, 1, max_list_len) end
    if #client_curves  > max_list_len then client_curves  = string_sub(client_curves,  1, max_list_len) end

    local t = {
        enabled        = true,
        protocol       = protocol,
        cipher         = get("ssl_cipher"),
        curve          = get("ssl_curve"),
        alpn           = get("ssl_alpn_protocol"),
        sni            = get("ssl_server_name"),
        session_reused = get("ssl_session_reused") == "r",
        early_data     = get("ssl_early_data") == "1",
        client_ciphers = client_ciphers,
        client_curves  = client_curves,
    }
    -- curve / alpn / sni / client_curves may legitimately be empty (no ALPN
    -- offered, no SNI, TLS 1.2 resumption); they do not make the capture partial.
    if t.cipher ~= "" and client_ciphers ~= "" then
        t.capture_status = _M.STATUS_COMPLETE
        -- Fingerprint only over a complete capture: a hash of a partial list
        -- would be a different, meaningless identity for the same client.
        local value = _M.fingerprint(client_ciphers)
        if value then
            t.fingerprint = { version = _M.FP_VERSION, algorithm = _M.FP_ALGORITHM, value = value }
        end
    else
        t.capture_status = _M.STATUS_PARTIAL
    end
    return t
end

------------------------------------------------------------------------------
-- Fingerprint karna-tls-v1
------------------------------------------------------------------------------
--
-- karna-tls-v1 is a JA3-like fingerprint reduced to the cipher suites the
-- client offered, the one ClientHello list nginx exposes for new AND resumed
-- sessions on every TLS version ($ssl_ciphers). Curves are deliberately out:
-- $ssl_curves is empty on a resumed TLS 1.2 session, so a client would carry
-- two identities. It is a property of the client, not of the server config:
-- nothing negotiated enters it.
--
-- Spec (the version string names ALL of this; a change means karna-tls-v2):
--   input     $ssl_ciphers as rendered by nginx: names for ciphers OpenSSL
--             knows, 0xNNNN (lowercase hex) for the rest, ":"-separated, in
--             the client's order.
--   GREASE    tokens 0x0a0a, 0x1a1a, ..., 0xfafa (RFC 8701; both bytes equal,
--             low nibble 0xa) are removed, matched case-insensitively. Every
--             other 0xNNNN token is kept — an unknown-to-the-server cipher is
--             information, not noise.
--   SCSV      TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00ff) is kept when present,
--             as JA3 does.
--   order     preserved (it is what distinguishes stacks that share a set).
--   canonical "karna-tls-v1|" .. tokens joined by ",", or "karna-tls-v1|-"
--             when nothing is left.
--   hash      SHA-256 of the canonical string, lowercase hex (64 chars).
--   status    computed only when capture_status == "complete"; absent on
--             partial captures and on plain HTTP.
-- The canonical string itself is never logged; it is available to tests and
-- to fingerprint_canonical() for debugging.

local function is_grease(token)
    -- lowercase to be safe: nginx renders lowercase hex, other sources may not
    local t = string.lower(token)
    if #t ~= 6 or string_sub(t, 1, 2) ~= "0x" then return false end
    local n1, n2 = string_sub(t, 3, 3), string_sub(t, 5, 5)
    return n1 == n2 and string_sub(t, 4, 4) == "a" and string_sub(t, 6, 6) == "a"
end
_M._is_grease = is_grease

-- Canonical string for a client cipher list. Returns canonical, kept, dropped.
function _M.fingerprint_canonical(client_ciphers)
    local kept, n, dropped = {}, 0, 0
    if type(client_ciphers) == "string" and client_ciphers ~= "" then
        local pos, len = 1, #client_ciphers
        while pos <= len + 1 do
            local sep = string.find(client_ciphers, ":", pos, true)
            local token = string_sub(client_ciphers, pos, (sep or (len + 1)) - 1)
            if token ~= "" then
                if is_grease(token) then
                    dropped = dropped + 1
                else
                    n = n + 1
                    kept[n] = token
                end
            end
            if not sep then break end
            pos = sep + 1
        end
    end
    local body = (n > 0) and table.concat(kept, ",") or "-"
    return _M.FP_VERSION .. "|" .. body, n, dropped
end

-- Default SHA-256 → hex primitive (resty.sha256); overridable (tests) via
-- _M.sha256_hex. nil when no implementation is available.
function _M.sha256_hex(s)
    local ok, sha256 = pcall(require, "resty.sha256")
    if not ok or not sha256 then return nil end
    local h = sha256:new()
    if not h then return nil end
    h:update(s)
    return to_hex(h:final())
end

-- Hash of the canonical string, cached per worker (canonical → hex).
function _M.fingerprint(client_ciphers)
    local canonical = _M.fingerprint_canonical(client_ciphers)
    local cache = _M._fp_cache
    if not cache then
        cache = _M.new_cache(_M.FP_CACHE_SIZE)
        _M._fp_cache = cache
    end
    local hit = cache:get(canonical)
    if hit then return hit end
    local ok, hex = pcall(_M.sha256_hex, canonical)
    if not ok or type(hex) ~= "string" or #hex ~= 64 then return nil end
    cache:set(canonical, hex)
    return hex
end

------------------------------------------------------------------------------
-- Connection id
------------------------------------------------------------------------------

-- Default primitives; each is overridable through init() opts (unit tests) and
-- degrades gracefully when the OpenResty library is not there.
function _M.random_bytes(n)
    local ok, rnd = pcall(require, "resty.random")
    if ok and rnd and rnd.bytes then
        local b = rnd.bytes(n, true) or rnd.bytes(n)
        if type(b) == "string" and #b == n then return b end
    end
    local out = {}
    for i = 1, n do out[i] = string.char(math.random(0, 255)) end
    return table.concat(out)
end

function _M.hmac_sha256(key, msg)
    local ok, hmac = pcall(require, "resty.openssl.hmac")
    if not ok or not hmac then return nil end
    local h, err = hmac.new(key, "sha256")
    if not h then return nil, err end
    return h:final(msg)
end

function _M.new_cache(size)
    local ok, lrucache = pcall(require, "resty.lrucache")
    if ok and lrucache then
        local c = lrucache.new(size)
        if c then return c end
    end
    -- plain-Lua fallback: bounded table, wiped when full
    local store, n = {}, 0
    return {
        get = function(_, k) return store[k] end,
        set = function(_, k, v)
            if n >= size then store, n = {}, 0 end
            if store[k] == nil then n = n + 1 end
            store[k] = v
        end,
    }
end

-- Per-worker state. opts (all optional): env_key (string; `false` = do not
-- read the environment), worker_id, random_bytes, hmac, cache, warn.
function _M.init(opts)
    opts = opts or {}
    local warn = opts.warn or function(msg)
        if ngx and ngx.log then ngx.log(ngx.WARN, "[karna] ", msg) end
    end
    local rnd = opts.random_bytes or _M.random_bytes

    local worker_id = opts.worker_id
    if worker_id == nil and ngx and ngx.worker and ngx.worker.id then
        worker_id = ngx.worker.id()
    end

    local env_key = opts.env_key
    if env_key == nil and os and os.getenv then
        env_key = os.getenv(_M.ENV_KEY_NAME)
    end

    local key, key_source
    if type(env_key) == "string" and #env_key >= _M.MIN_KEY_LEN then
        key, key_source = env_key, "env"
    else
        key, key_source = rnd(32), "random"
        if type(env_key) == "string" and env_key ~= "" then
            warn(_M.ENV_KEY_NAME .. " is shorter than " .. _M.MIN_KEY_LEN
                 .. " bytes: ignored, using a random per-worker key (connection ids"
                 .. " stay stable within this worker's lifetime only)")
        else
            warn(_M.ENV_KEY_NAME .. " not set: using a random per-worker key"
                 .. " (connection ids stay stable within this worker's lifetime only)")
        end
    end

    _M._state = {
        key        = key,
        key_source = key_source,
        nonce      = to_hex(rnd(16)),
        worker_id  = tostring(worker_id or 0),
        cache      = opts.cache or _M.new_cache(_M.CACHE_SIZE),
        hmac       = opts.hmac or _M.hmac_sha256,
    }
    return _M._state
end

-- The id for the connection carrying `var` (needs var.connection). nil when
-- init() has not run or the serial is unavailable.
function _M.connection_id(var)
    local st = _M._state
    if not st then return nil end
    local conn = var and var.connection
    if type(conn) ~= "string" or conn == "" then return nil end

    local cached = st.cache:get(conn)
    if cached then return cached end

    local raw = st.hmac(st.key, "kc1|" .. st.nonce .. "|" .. st.worker_id .. "|" .. conn)
    if type(raw) ~= "string" or #raw < 16 then return nil end

    local id = _M.ID_PREFIX .. to_hex(string_sub(raw, 1, 16))
    st.cache:set(conn, id)
    return id
end

------------------------------------------------------------------------------
-- Per-request wiring
------------------------------------------------------------------------------

-- Read once per request into ctx.tls / ctx.connection_id. Idempotent.
function _M.populate(ctx, var)
    ctx = ctx or plugin_ctx()
    var = var or (ngx and ngx.var)
    if not ctx then return nil end
    if ctx.tls then return ctx.tls end
    ctx.tls = _M.collect(var)
    ctx.connection_id = _M.connection_id(var)
    return ctx.tls
end

local function as_string(v)
    if type(v) == "boolean" then return v and "true" or "false" end
    return tostring(v)
end

-- Rule variable value for `tls.<field>` / `connection.id`, or nil when the
-- variable does not resolve (no TLS, unknown field, not populated).
-- `tls.enabled` and `tls.capture_status` always resolve once populated.
function _M.resolve_variable(name, ctx)
    ctx = ctx or plugin_ctx()
    if not ctx then return nil end
    if name == "connection.id" then return ctx.connection_id end
    local t = ctx.tls
    if not t then return nil end
    local short = string_sub(name, 5)                 -- after "tls."
    if short == "enabled"        then return as_string(t.enabled) end
    if short == "capture_status" then return t.capture_status end
    if not t.enabled then return nil end
    if short == "fingerprint" then
        return t.fingerprint and t.fingerprint.value or nil
    end
    if short == "fingerprint_version" then
        return t.fingerprint and t.fingerprint.version or nil
    end
    local v = t[short]
    if v == nil or type(v) == "table" then return nil end
    return as_string(v)
end

-- Rows for the macro inspection table (%{connection.id}, %{tls.sni}, ...).
function _M.populate_inspection_table(tbl, ctx)
    ctx = ctx or plugin_ctx()
    if not ctx or type(tbl) ~= "table" then return end
    if ctx.connection_id then
        tbl[#tbl + 1] = { ["connection.id"] = ctx.connection_id }
    end
    local t = ctx.tls
    if not t then return end
    tbl[#tbl + 1] = { ["tls.enabled"]        = as_string(t.enabled) }
    tbl[#tbl + 1] = { ["tls.capture_status"] = t.capture_status }
    if not t.enabled then return end
    for _, f in ipairs(_M.FIELDS) do
        if t[f] ~= nil then
            tbl[#tbl + 1] = { ["tls." .. f] = as_string(t[f]) }
        end
    end
    if t.fingerprint then
        tbl[#tbl + 1] = { ["tls.fingerprint"]         = t.fingerprint.value }
        tbl[#tbl + 1] = { ["tls.fingerprint_version"] = t.fingerprint.version }
    end
end

-- JSON-ready audit blocks: `network` (nil when no connection id) and `tls`
-- (nil when not populated). Booleans stay booleans here.
function _M.audit_blocks(ctx)
    ctx = ctx or plugin_ctx()
    if not ctx then return nil, nil end
    local network
    if ctx.connection_id then
        network = { connection_id = ctx.connection_id }
    end
    local t = ctx.tls
    if not t then return network, nil end
    local tls = { enabled = t.enabled, capture_status = t.capture_status }
    if t.enabled then
        for _, f in ipairs(_M.FIELDS) do tls[f] = t[f] end
        if t.fingerprint then
            tls.fingerprint = { version   = t.fingerprint.version,
                                algorithm = t.fingerprint.algorithm,
                                value     = t.fingerprint.value }
        end
    end
    return network, tls
end

return _M
