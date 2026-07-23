-- ka_global_rules.lua — centrally distributed global rules, pulled from Redis.
--
-- Karna instances are attached per-service, so there is no Kong-native way to
-- ship one rule pack to every service (a global plugin instance would be
-- shadowed by the per-service ones — Kong runs a single instance of a plugin
-- per request). This module closes that gap: operators publish a rule pack to
-- a single Redis hash and every worker on every node pulls it, verifies it,
-- and evaluates it on every service BEFORE local rules and the CRS pack.
--
-- Redis layout — one hash key, `karna:global_rules`, four fields:
--   json     raw JSON array of rules in the Karna rule format (same shape as
--            `rules_request` entries)
--   seclang  raw SecLang text (same dialect as `custom_secrules`)
--   version  monotonically increasing integer, bumped on every publish
--   sig      hex HMAC-SHA256 over `version .. "\n" .. sha256hex(json) ..
--            "\n" .. sha256hex(seclang)` — see `signing_message`
-- A single HSET updates all four fields atomically; readers HGET `version`
-- as a cheap poll and HGETALL only when it changes. Publish with
-- `scripts/karna-rules.py --type global-rules`.
--
-- Trust model: Redis is a TRANSPORT, not a trust anchor. When
-- KARNA_GLOBAL_RULES_HMAC_KEY is set, a pack with a missing or invalid
-- signature is rejected and the last known good pack stays active — write
-- access to Redis alone is not enough to inject or weaken rules. Without the
-- key the pack is accepted unsigned (a loud startup warning marks the
-- posture). Residual risk with the key set: an actor with Redis write access
-- can replay an OLD signed pack; workers refuse non-increasing versions for
-- their lifetime, so the replay window is a worker restart. Rotate the key to
-- invalidate old signatures outright.
--
-- Environment (worker env — remember nginx wipes env unless declared with
-- `env NAME;` in the main context, see docker/main-env.conf):
--   KARNA_REDIS_URL              redis://[user][:pass]@host[:port][/db] or
--                                rediss:// for TLS. Unset = feature disabled,
--                                zero overhead.
--   KARNA_GLOBAL_RULES_HMAC_KEY  shared HMAC key; unset = unsigned mode.
--   KARNA_GLOBAL_RULES_POLL      poll interval seconds (default 30, min 5).
--
-- init_worker cannot use cosockets, so `init()` only schedules timers: an
-- immediate one-shot load plus a recurring poll. Until the first successful
-- load the pack is empty (cold-start window ≤ one poll on a Redis outage).
-- Failure posture: connection/verify/parse failures KEEP the last known good
-- pack; an explicitly deleted hash CLEARS it (absence is a valid published
-- state, an error is not).

local seclang = require "kong.plugins.karna.ka_seclang"
local cjson   = require "cjson"

local _M = {}

_M.REDIS_KEY = "karna:global_rules"

-- Injected by handler.lua at init (dependency injection keeps this module
-- requirable from plain-Lua unit tests without dragging in the engine):
--   _M._engine  → ka_engine (for the pmFromFile dfiles merge)
--   _M._compile → ka_compile.compile_rules
_M._engine  = nil
_M._compile = nil

-- Current pack. Swapped atomically (table reference assignment) by the
-- polling timer; readers (`get()`) never see a half-built pack.
_M._pack = nil
_M._last_version = nil      -- string, as stored in Redis (cheap poll compare)
_M._last_version_num = nil  -- number, for the monotonicity check
_M._warned_unsigned = false

-- ---------------------------------------------------------------------------
-- crypto — lua-resty-openssl (bundled with Kong). pcall'd so plain-Lua unit
-- tests can stub `_M._sha256_hex` / `_M._hmac_sha256_hex` instead.
-- ---------------------------------------------------------------------------

local function to_hex(s)
    return (s:gsub(".", function(c) return string.format("%02x", string.byte(c)) end))
end

_M._sha256_hex = function(s)
    local ok, digest = pcall(require, "resty.openssl.digest")
    if not ok then return nil, "resty.openssl.digest unavailable" end
    local d, err = digest.new("sha256")
    if not d then return nil, err end
    local bin, derr = d:final(s)
    if not bin then return nil, derr end
    return to_hex(bin)
end

_M._hmac_sha256_hex = function(key, msg)
    local ok, hmac = pcall(require, "resty.openssl.hmac")
    if not ok then return nil, "resty.openssl.hmac unavailable" end
    local h, err = hmac.new(key, "sha256")
    if not h then return nil, err end
    local bin, ferr = h:final(msg)
    if not bin then return nil, ferr end
    return to_hex(bin)
end

-- Constant-time string compare. Length is not secret (hex HMAC output is
-- fixed-width); content must not leak through timing.
local function constant_time_eq(a, b)
    if type(a) ~= "string" or type(b) ~= "string" then return false end
    if #a ~= #b then return false end
    local acc = 0
    for i = 1, #a do
        acc = acc + (string.byte(a, i) == string.byte(b, i) and 0 or 1)
    end
    return acc == 0
end

-- The exact byte string both sides sign. Inner digests (not raw
-- concatenation) frame the two payloads, so bytes cannot migrate between
-- fields and produce the same message; the version binds the signature to
-- one specific publish. MUST stay in lockstep with `_sign_message()` in
-- scripts/karna-rules.py.
_M.signing_message = function(version, json_blob, seclang_blob)
    local jh, jerr = _M._sha256_hex(json_blob or "")
    if not jh then return nil, jerr end
    local sh, serr = _M._sha256_hex(seclang_blob or "")
    if not sh then return nil, serr end
    return tostring(version or "") .. "\n" .. jh .. "\n" .. sh
end

-- ---------------------------------------------------------------------------
-- config
-- ---------------------------------------------------------------------------

-- redis://[user][:password]@host[:port][/db], rediss:// = TLS.
-- Returns {host, port, user, password, database, ssl} or nil, err.
_M.parse_redis_url = function(url)
    if type(url) ~= "string" or url == "" then return nil, "empty url" end

    local scheme, rest = url:match("^(redis[s]?)://(.*)$")
    if not scheme then return nil, "unsupported scheme (want redis:// or rediss://)" end

    local conf = { ssl = (scheme == "rediss"), port = 6379, database = 0 }

    -- split credentials from host part on the LAST @ (passwords may contain @)
    local creds, hostpart
    local at = rest:match(".*()@")
    if at then
        creds = rest:sub(1, at - 1)
        hostpart = rest:sub(at + 1)
    else
        hostpart = rest
    end

    if creds and creds ~= "" then
        local user, pass = creds:match("^([^:]*):(.*)$")
        if pass then
            if user ~= "" then conf.user = user end
            if pass ~= "" then conf.password = pass end
        else
            -- bare "user@" with no colon — Redis 6 ACL user without password
            -- makes no sense for AUTH; treat the whole blob as a password.
            conf.password = creds
        end
    end

    local hp, db = hostpart:match("^([^/]+)/?(%d*)$")
    if not hp or hp == "" then return nil, "missing host" end
    if db and db ~= "" then conf.database = tonumber(db) end

    local h, p = hp:match("^(.+):(%d+)$")
    if h then
        conf.host = h
        conf.port = tonumber(p)
    else
        conf.host = hp
    end

    return conf
end

_M._config = nil
_M.config = function()
    if _M._config ~= nil then return _M._config end

    local url = os.getenv("KARNA_REDIS_URL")
    if not url or url == "" then
        _M._config = false  -- memoized "disabled"
        return false
    end

    local conf, err = _M.parse_redis_url(url)
    if not conf then
        kong.log.err("[karna] global rules: bad KARNA_REDIS_URL (", err, ") — feature disabled")
        _M._config = false
        return false
    end

    conf.hmac_key = os.getenv("KARNA_GLOBAL_RULES_HMAC_KEY")
    if conf.hmac_key == "" then conf.hmac_key = nil end

    local poll = tonumber(os.getenv("KARNA_GLOBAL_RULES_POLL") or "")
    if not poll or poll < 5 then poll = poll and 5 or 30 end
    conf.poll = poll

    _M._config = conf
    return conf
end

-- ---------------------------------------------------------------------------
-- verify
-- ---------------------------------------------------------------------------

-- fields = the HGETALL result. Returns true, or nil + reason.
_M.verify = function(fields, hmac_key)
    if not hmac_key then
        if not _M._warned_unsigned then
            _M._warned_unsigned = true
            kong.log.warn("[karna] global rules: KARNA_GLOBAL_RULES_HMAC_KEY not set — ",
                          "accepting UNSIGNED packs. Anyone with Redis write access ",
                          "can alter WAF behaviour; set the key to require signatures.")
        end
        return true
    end

    if not fields.sig or fields.sig == "" then
        return nil, "signature required but missing"
    end

    local msg, merr = _M.signing_message(fields.version, fields.json, fields.seclang)
    if not msg then return nil, "cannot build signing message: " .. tostring(merr) end

    local want, herr = _M._hmac_sha256_hex(hmac_key, msg)
    if not want then return nil, "cannot compute hmac: " .. tostring(herr) end

    if not constant_time_eq(want, fields.sig:lower()) then
        return nil, "signature mismatch"
    end
    return true
end

-- ---------------------------------------------------------------------------
-- build — parse the two payloads into one compiled, phase-split pack
-- ---------------------------------------------------------------------------

local function empty_pack(version)
    return { all = {}, access = {}, header_filter = {}, mcp_event = {},
             version = version, n_json = 0, n_seclang = 0, n_dropped = 0 }
end

-- Numeric-aware id sort, same policy as the CRS loader in ka_engine:
-- SecLang parse returns a `{[id] = rule}` hash and LuaJIT hash order differs
-- across workers — without an explicit sort, first-match-wins would fire a
-- different rule per worker for multi-rule matches.
local function sorted_ids(hash)
    local ids = {}
    for id in pairs(hash) do ids[#ids + 1] = id end
    table.sort(ids, function(a, b)
        local an, bn = tonumber(a), tonumber(b)
        if an and bn then return an < bn end
        if an and not bn then return false end
        if bn and not an then return true end
        return tostring(a) < tostring(b)
    end)
    return ids
end

-- A rule the engine could not possibly evaluate is dropped loudly rather
-- than kept as dead weight that LOOKS like protection.
local function rule_is_sane(rule)
    return type(rule) == "table"
       and rule.id ~= nil
       and type(rule.phase) == "string"
       and type(rule.conditions) == "table"
end

-- Resolve @pmFromFile data files against the CRS rules dir (the only rule
-- data present on every node — the global pack itself ships no files).
-- Returns true + dfiles-merged, or false when a data file is missing (the
-- rule is dropped: a pmFromFile with no file never matches, keeping it
-- would be silent fail-open).
local function resolve_dfiles(rule, dfiles)
    for _, condition in pairs(rule.conditions or {}) do
        if condition.op == "pmFromFile" and condition.value then
            if not dfiles[condition.value] then
                local content = seclang.collect_data_file(seclang.crs_path .. condition.value)
                if not content then
                    return false, condition.value
                end
                dfiles[condition.value] = content
            end
        end
    end
    return true
end

-- fields.json / fields.seclang → pack. Never throws; unparseable payloads
-- return nil + err so the caller keeps the last known good pack.
_M.build = function(fields)
    local pack = empty_pack(fields.version)
    local dfiles = {}

    -- 1) JSON payload: a single JSON array, author order preserved.
    local json_blob = fields.json
    if json_blob and json_blob ~= "" then
        local ok, decoded = pcall(cjson.decode, json_blob)
        if not ok or type(decoded) ~= "table" then
            return nil, "json payload is not a valid JSON array: " .. tostring(decoded)
        end
        for i, rule in ipairs(decoded) do
            if not rule_is_sane(rule) then
                pack.n_dropped = pack.n_dropped + 1
                kong.log.err("[karna] global rules: json rule #", i,
                             " dropped (needs id, phase, conditions)")
            else
                local okd, missing = resolve_dfiles(rule, dfiles)
                if not okd then
                    pack.n_dropped = pack.n_dropped + 1
                    kong.log.warn("[karna] global rules: rule ", tostring(rule.id),
                                  " dropped — pmFromFile data file not found: ", missing)
                else
                    if rule.log == nil then rule.log = true end
                    pack.all[#pack.all + 1] = rule
                    pack.n_json = pack.n_json + 1
                end
            end
        end
    end

    -- 2) SecLang payload, parsed in isolation (same path as custom_secrules),
    --    appended AFTER the JSON rules, sorted by id for determinism.
    local seclang_blob = fields.seclang
    if seclang_blob and seclang_blob ~= "" then
        local ok, parsed = pcall(seclang.parse_isolated, seclang_blob)
        if not ok then
            return nil, "seclang payload failed to parse: " .. tostring(parsed)
        end
        for _, id in ipairs(sorted_ids(parsed)) do
            local rule = parsed[id]
            local okd, missing = resolve_dfiles(rule, dfiles)
            if not okd then
                pack.n_dropped = pack.n_dropped + 1
                kong.log.warn("[karna] global rules: rule ", tostring(rule.id),
                              " dropped — pmFromFile data file not found: ", missing)
            else
                if rule.log == nil then rule.log = true end
                pack.all[#pack.all + 1] = rule
                pack.n_seclang = pack.n_seclang + 1
            end
        end
    end

    -- 3) phase split (same precomputed-views contract as
    --    handler.lua:get_local_request_rules)
    for _, rule in ipairs(pack.all) do
        if rule.phase == "access" then
            pack.access[#pack.access + 1] = rule
        elseif rule.phase == "header_filter" then
            pack.header_filter[#pack.header_filter + 1] = rule
        elseif rule.phase == "mcp_event" then
            pack.mcp_event[#pack.mcp_event + 1] = rule
        end
    end

    -- 4) compile to closures (nil plugin_conf, same as the CRS init path)
    if _M._compile and #pack.all > 0 then
        pcall(_M._compile, pack.all, nil)
    end

    pack.dfiles = dfiles
    return pack
end

_M.apply = function(pack)
    _M._pack = pack
    -- Merge pmFromFile data files into the engine's live dfile store so the
    -- pm matcher finds them. Additive: global packs only ever reference CRS
    -- data files already on disk, so entries are identical across reloads.
    if _M._engine and pack.dfiles then
        _M._engine._ka_dfiles = _M._engine._ka_dfiles or {}
        for k, v in pairs(pack.dfiles) do
            _M._engine._ka_dfiles[k] = v
            -- invalidate the lowercased memo for this file, if the engine
            -- keeps one (see ka_engine load_rules)
            if _M._engine._ka_dfiles_lower then
                _M._engine._ka_dfiles_lower[k] = nil
            end
        end
    end
end

_M.get = function()
    return _M._pack
end

-- ---------------------------------------------------------------------------
-- redis fetch + poll
-- ---------------------------------------------------------------------------

local function arr_to_hash(arr)
    local h = {}
    for i = 1, #arr, 2 do h[arr[i]] = arr[i + 1] end
    return h
end

local function redis_open(conf)
    local redis = require "resty.redis"
    local red = redis:new()
    red:set_timeouts(2000, 2000, 2000)

    local opts
    if conf.ssl then
        opts = { ssl = true, ssl_verify = false, server_name = conf.host }
    end
    local ok, err = red:connect(conf.host, conf.port, opts)
    if not ok then return nil, "connect: " .. tostring(err) end

    if conf.password then
        local aok, aerr
        if conf.user then aok, aerr = red:auth(conf.user, conf.password)
        else aok, aerr = red:auth(conf.password) end
        if not aok then red:close(); return nil, "auth: " .. tostring(aerr) end
    end

    if conf.database and conf.database > 0 then
        local sok, serr = red:select(conf.database)
        if not sok then red:close(); return nil, "select: " .. tostring(serr) end
    end

    return red
end

-- One poll round. Returns "unchanged" | "applied" | "cleared" | nil, err.
-- Exposed on _M so tests can drive it with a stubbed resty.redis.
_M._tick = function()
    local conf = _M.config()
    if not conf then return nil, "disabled" end

    local red, oerr = redis_open(conf)
    if not red then return nil, oerr end

    -- cheap poll: version only
    local version, verr = red:hget(_M.REDIS_KEY, "version")
    if verr then red:close(); return nil, "hget: " .. tostring(verr) end

    if version == ngx.null or version == nil then
        -- Hash deleted (or never published): absence is a valid state.
        red:set_keepalive(10000, 2)
        if _M._pack and #_M._pack.all > 0 then
            _M.apply(empty_pack(nil))
            _M._last_version, _M._last_version_num = nil, nil
            kong.log.notice("[karna] global rules: pack removed from Redis — cleared")
            return "cleared"
        end
        return "unchanged"
    end

    if version == _M._last_version then
        red:set_keepalive(10000, 2)
        return "unchanged"
    end

    -- version changed: full fetch (single HGETALL = consistent snapshot)
    local arr, gerr = red:hgetall(_M.REDIS_KEY)
    red:set_keepalive(10000, 2)
    if not arr then return nil, "hgetall: " .. tostring(gerr) end
    local fields = arr_to_hash(arr)

    -- monotonicity: refuse replays of an older signed pack
    local vnum = tonumber(fields.version)
    if not vnum then
        return nil, "version is not a number: " .. tostring(fields.version)
    end
    if _M._last_version_num and vnum <= _M._last_version_num then
        return nil, "version rollback refused (have "
                    .. tostring(_M._last_version_num) .. ", got " .. tostring(vnum) .. ")"
    end

    local okv, why = _M.verify(fields, conf.hmac_key)
    if not okv then return nil, "pack rejected: " .. tostring(why) end

    local pack, berr = _M.build(fields)
    if not pack then return nil, "pack rejected: " .. tostring(berr) end

    _M.apply(pack)
    _M._last_version = fields.version
    _M._last_version_num = vnum
    kong.log.notice("[karna] global rules: applied pack version ", fields.version,
                    " (", pack.n_json, " json + ", pack.n_seclang, " seclang rules",
                    pack.n_dropped > 0 and (", " .. pack.n_dropped .. " dropped") or "",
                    ", worker ", ngx.worker.id() or "?", ")")
    return "applied"
end

local function timer_tick(premature)
    if premature then return end
    local res, err = _M._tick()
    if not res and err ~= "disabled" then
        -- Last known good pack stays active; say so, once per failed poll.
        kong.log.err("[karna] global rules: poll failed (", err,
                     ") — keeping last known good pack")
    end
end

-- Called from handler.lua init_worker. Cosockets are unavailable there, so
-- this only schedules: one immediate load + the recurring poll.
_M.init = function(opts)
    opts = opts or {}
    _M._engine  = opts.engine or _M._engine
    _M._compile = opts.compile or _M._compile

    local conf = _M.config()
    if not conf then
        kong.log.debug("[karna] global rules: KARNA_REDIS_URL not set — disabled")
        return false
    end

    local ok, err = ngx.timer.at(0, timer_tick)
    if not ok then
        kong.log.err("[karna] global rules: failed to schedule initial load: ", err)
    end
    local ok2, err2 = ngx.timer.every(conf.poll, timer_tick)
    if not ok2 then
        kong.log.err("[karna] global rules: failed to schedule poll timer: ", err2)
    end

    kong.log.notice("[karna] global rules: enabled — redis ", conf.host, ":",
                    tostring(conf.port), (conf.ssl and " (tls)" or ""),
                    ", poll ", tostring(conf.poll), "s, ",
                    conf.hmac_key and "HMAC signature REQUIRED" or "UNSIGNED mode")
    return true
end

return _M
