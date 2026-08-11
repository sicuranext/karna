-- ka_global_rules.lua — global rules: one rule pack evaluated on EVERY
-- service Karna is attached to, BEFORE local rules and the CRS pack.
--
-- Karna instances are attached per-service, so there is no Kong-native way to
-- ship one rule pack to every service (a global plugin instance would be
-- shadowed by the per-service ones — Kong runs a single instance of a plugin
-- per request). This module closes that gap, from two independent and
-- individually optional sources:
--
--   DISK   KARNA_GLOBAL_RULES_PATH — a .json file, or a directory whose
--          `*.json` files are loaded in filename order. Each file is a bare
--          JSON array of rules in the Karna rule format: the same array
--          `rules_request` carries, and the same payload published to Redis
--          as the `json` field, so a pack can be moved between the two
--          channels verbatim. No SecLang on this channel.
--          Read synchronously at init_worker — file I/O needs no cosockets,
--          so the pack is live before the first request. There is no
--          filesystem watcher by design: changing the file takes effect on
--          `kong reload` (which respawns workers) or a restart.
--          The pack is NOT signed — on disk the filesystem is the trust
--          anchor, exactly as for the CRS rules and the CRS plugin dirs.
--
--   REDIS  KARNA_REDIS_URL — polled, HMAC-verified, hot-swapped with no
--          reload. Details below.
--
-- Both sources feed the same `build_sources()` and are then merged by
-- `recombine()` into the single pack `get()` returns. Two contracts hold
-- across the merge:
--
--   ORDER   disk before Redis. Within one source, author order (files in
--           filename order, rules in array order).
--   DEDUP   first-wins on rule id, across sources and files: the disk pack
--           is authoritative, so Redis can ADD rules but cannot silently
--           replace a rule deployed on disk with a weaker one carrying the
--           same id. Later duplicates are discarded with a warning.
--
-- Each pack is split in two lists, and the split is what makes rule order
-- inside a file irrelevant:
--
--   controls   rules with `rule_control` and no `action` — CRS-style
--              exclusions. Evaluated on the multi-match path, so every
--              matching exclusion contributes its ctl:* side effects.
--   detection  everything else, evaluated on the standard first-terminal-
--              wins path with the full action dispatch (fixed_response,
--              fix_matched_parts, rate_limit, set_variable, setvar, …).
--              A rule carrying `rule_control` PLUS another action stays
--              here, so it keeps that dispatch.
--
-- `@pmFromFile` is not supported on this channel (either source): a rule
-- using it is dropped with a warning rather than kept as a condition that
-- can never match, which would be silent fail-open. Global packs therefore
-- never touch the engine's shared data-file store.
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
--   KARNA_GLOBAL_RULES_PATH      .json file or directory of *.json files.
--                                Unset = disk source disabled, no I/O at all.
--   KARNA_REDIS_URL              redis://[user][:pass]@host[:port][/db] or
--                                rediss:// for TLS. Unset = Redis source
--                                disabled, zero overhead.
--   KARNA_GLOBAL_RULES_HMAC_KEY  shared HMAC key; unset = unsigned mode.
--   KARNA_GLOBAL_RULES_POLL      poll interval seconds (default 30, min 5).
--
-- The two sources are independent: either can run without the other.
--
-- Failure posture — fail-open, granular, loud:
--   * a rule the engine could not evaluate (missing id/phase/conditions, or
--     an unsupported @pmFromFile) is dropped; the rest of the pack stays
--     active.
--   * a file that cannot be read or does not decode is skipped with an
--     error; the other files in the directory still load.
--   * for Redis, connection/verify/parse failures KEEP the last known good
--     pack, while an explicitly deleted hash CLEARS it (absence is a valid
--     published state, an error is not).
-- A broken global pack therefore never takes a node down — it shows up as
-- ERR/WARN lines at load time, which is why those lines name the rule id and
-- the reason.
--
-- init_worker cannot use cosockets, so the Redis half of `init()` only
-- schedules timers: an immediate one-shot load plus a recurring poll. Until
-- the first successful load the Redis pack is empty (cold-start window ≤ one
-- poll on a Redis outage). The disk half has no such window: it is read
-- inline, before the worker serves anything.

local seclang = require "kong.plugins.karna.ka_seclang"
local cjson   = require "cjson"

local _M = {}

_M.REDIS_KEY = "karna:global_rules"

-- The phases a global pack is evaluated in. `body_filter` is absent on
-- purpose: same as local rules, response bodies are only inspected through
-- the MCP SSE path (`mcp_event`).
local PHASES = { "access", "header_filter", "mcp_event" }

-- Injected by handler.lua at init (dependency injection keeps this module
-- requirable from plain-Lua unit tests without dragging in the engine):
--   _M._engine  → ka_engine (for the pmFromFile dfiles merge)
--   _M._compile → ka_compile.compile_rules
_M._engine  = nil
_M._compile = nil

-- Per-source packs plus the merged view served to the request path. All three
-- are swapped by whole-table reference assignment, so readers (`get()`) never
-- see a half-built pack: the disk pack is built once at init_worker, the Redis
-- pack by the polling timer, and `recombine()` publishes a fresh merged table.
_M._file_pack = nil
_M._redis_pack = nil
_M._combined = nil          -- what get() returns; nil while both sources are empty
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
-- build — turn payload sources (files, or the Redis json/seclang fields) into
-- one compiled pack, split controls/detection and then per phase
-- ---------------------------------------------------------------------------

local function empty_pack(version)
    local pack = {
        all = {}, controls = {}, detection = {},
        version = version,
        n_json = 0, n_seclang = 0, n_dropped = 0,
        n_controls = 0, n_detection = 0,
    }
    for _, phase in ipairs(PHASES) do
        pack.controls[phase] = {}
        pack.detection[phase] = {}
    end
    return pack
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

-- @pmFromFile is unsupported on the global channel — see the header. Catches
-- both the canonical `{op="pmFromFile", negated=…}` shape and the legacy
-- `!pmFromFile` shorthand the engine still accepts on input.
local function uses_pmfromfile(rule)
    for _, condition in pairs(rule.conditions or {}) do
        if condition.op == "pmFromFile" or condition.op == "!pmFromFile" then
            return true
        end
    end
    return false
end

-- Exclusion rules (only `rule_control`, no action) go on the multi-match
-- controls path; everything else keeps the standard action dispatch. A rule
-- carrying `rule_control` NEXT TO a real action stays in detection, because
-- the controls path deliberately does not run action side effects
-- (set_variable / set_log_fields / redis_incr_key would be silently lost).
--
-- Duplicated on purpose: `ka_compile.is_control_only` is the canonical copy and
-- is what handler.lua uses to split the per-plugin dynamic rules. This module
-- deliberately requires neither ka_compile nor the engine (both are injected via
-- init()) so it stays requirable from plain-Lua unit tests, so it carries its
-- own. The two MUST stay in lockstep — a rule has to be filed the same way
-- whichever channel it arrives on. Covered by ka-unittest/custom_secrules_split.lua.
local function is_control_only(rule)
    if type(rule.rule_control) ~= "table" then return false end
    local action = rule.action
    if action == nil then return true end
    if type(action) ~= "table" then return false end
    return next(action) == nil
end

-- Vet one rule and file it into the pack. `label` names the source in the log
-- line (a filename, or "redis"); `position` is a human hint for rules that
-- have no usable id. Returns true when the rule was kept.
local function add_rule(pack, rule, label, position)
    if not rule_is_sane(rule) then
        pack.n_dropped = pack.n_dropped + 1
        kong.log.err("[karna] global rules: ", label, " rule ", position,
                     " dropped (needs id, phase, conditions)")
        return false
    end

    if uses_pmfromfile(rule) then
        pack.n_dropped = pack.n_dropped + 1
        kong.log.warn("[karna] global rules: ", label, " rule ", tostring(rule.id),
                      " dropped — @pmFromFile is not supported in global rules")
        return false
    end

    local is_control = is_control_only(rule)
    local bucket = is_control and pack.controls or pack.detection
    local phase_list = bucket[rule.phase]
    if not phase_list then
        -- Sane but unreachable: a phase this channel never evaluates
        -- (body_filter, or a typo). Dropped rather than parked in the pack
        -- looking like coverage it does not provide.
        pack.n_dropped = pack.n_dropped + 1
        kong.log.warn("[karna] global rules: ", label, " rule ", tostring(rule.id),
                      " dropped — phase '", tostring(rule.phase),
                      "' is not evaluated for global rules")
        return false
    end

    if rule.log == nil then rule.log = true end

    -- Where this rule came from (filename, or "redis"). Only used to make the
    -- duplicate-id warning actionable — it names both sides of the clash.
    rule._ka_origin = label

    pack.all[#pack.all + 1] = rule
    phase_list[#phase_list + 1] = rule
    if is_control then
        pack.n_controls = pack.n_controls + 1
    else
        pack.n_detection = pack.n_detection + 1
    end
    return true
end

-- Build one pack out of an ordered list of payload sources, each
-- `{name = <label>, json = <blob>, seclang = <blob>}`. Never throws.
-- Returns `pack, errors` where `errors` is a (possibly empty) list of
-- per-source failure strings — a source whose payload does not decode
-- contributes an error and no rules; the callers differ in how they react
-- (Redis rejects the whole pack and keeps the last known good, the disk
-- loader skips the bad file and keeps the others).
_M.build_sources = function(sources, version)
    local pack = empty_pack(version)
    local errors = {}

    for _, source in ipairs(sources or {}) do
        local label = source.name or "?"

        -- JSON payload: a bare JSON array, author order preserved.
        local json_blob = source.json
        if json_blob and json_blob ~= "" then
            local ok, decoded = pcall(cjson.decode, json_blob)
            if not ok or type(decoded) ~= "table" then
                errors[#errors + 1] = label ..
                    ": json payload is not a valid JSON array: " .. tostring(decoded)
            elseif decoded[1] == nil and next(decoded) ~= nil then
                -- Decodes fine but is an object, not an array — the likely
                -- authoring mistake is wrapping the rules in an envelope
                -- ({"rules": [...]}). Say so instead of silently loading zero
                -- rules from a file that looks fine.
                errors[#errors + 1] = label ..
                    ": json payload must be an ARRAY of rules, got a JSON object"
            else
                for i, rule in ipairs(decoded) do
                    if add_rule(pack, rule, label, "#" .. tostring(i)) then
                        pack.n_json = pack.n_json + 1
                    end
                end
            end
        end

        -- SecLang payload (Redis channel only), parsed in isolation — the
        -- same path as custom_secrules. Appended AFTER this source's JSON
        -- rules and sorted by id, because seclang.parse returns a hash whose
        -- LuaJIT iteration order differs across workers.
        local seclang_blob = source.seclang
        if seclang_blob and seclang_blob ~= "" then
            local ok, parsed = pcall(seclang.parse_isolated, seclang_blob)
            if not ok then
                errors[#errors + 1] = label ..
                    ": seclang payload failed to parse: " .. tostring(parsed)
            else
                for _, id in ipairs(sorted_ids(parsed)) do
                    if add_rule(pack, parsed[id], label, tostring(id)) then
                        pack.n_seclang = pack.n_seclang + 1
                    end
                end
            end
        end
    end

    -- Compile to closures (nil plugin_conf, same as the CRS init path).
    if _M._compile and #pack.all > 0 then
        pcall(_M._compile, pack.all, nil)
    end

    return pack, errors
end

-- Redis entry point: one source, all-or-nothing. Unparseable payloads return
-- nil + err so the caller keeps the last known good pack.
_M.build = function(fields)
    local pack, errors = _M.build_sources(
        { { name = "redis", json = fields.json, seclang = fields.seclang } },
        fields.version)
    if #errors > 0 then
        return nil, errors[1]
    end
    return pack
end

-- Merge the per-source packs into the single view the request path reads.
-- Order is disk then Redis, controls then detection; dedup is first-wins on
-- rule id across the whole merged pack, so the disk pack is authoritative and
-- a duplicate id can never quietly shadow it. Rebuilt from scratch on every
-- change and published by reference assignment, so a request in flight keeps
-- reading the previous merged table.
_M.recombine = function()
    local combined = {
        all = {}, controls = {}, detection = {},
        n_duplicates = 0, duplicate_ids = {},
    }
    for _, phase in ipairs(PHASES) do
        combined.controls[phase] = {}
        combined.detection[phase] = {}
    end

    local seen = {}
    local steps = {
        { pack = _M._file_pack,  kind = "controls",  source = "file"  },
        { pack = _M._redis_pack, kind = "controls",  source = "redis" },
        { pack = _M._file_pack,  kind = "detection", source = "file"  },
        { pack = _M._redis_pack, kind = "detection", source = "redis" },
    }

    for _, step in ipairs(steps) do
        if step.pack then
            for _, phase in ipairs(PHASES) do
                local target = combined[step.kind][phase]
                for _, rule in ipairs(step.pack[step.kind][phase]) do
                    local id = tostring(rule.id)
                    local owner = seen[id]
                    if owner then
                        combined.n_duplicates = combined.n_duplicates + 1
                        combined.duplicate_ids[#combined.duplicate_ids + 1] = id
                        kong.log.warn("[karna] global rules: duplicate rule id ", id,
                                      " from ", step.source, " (",
                                      tostring(rule._ka_origin), ", ", step.kind, "/", phase,
                                      ") discarded — already provided by ", owner)
                    else
                        seen[id] = step.source .. " (" .. tostring(rule._ka_origin) ..
                                   ", " .. step.kind .. "/" .. phase .. ")"
                        target[#target + 1] = rule
                        combined.all[#combined.all + 1] = rule
                    end
                end
            end
        end
    end

    _M._combined = combined
    return combined
end

-- Redis pack swap. Kept as `apply` for the poll state machine's benefit.
_M.apply = function(pack)
    _M._redis_pack = pack
    _M.recombine()
end

_M.get = function()
    return _M._combined
end

-- ---------------------------------------------------------------------------
-- disk source
-- ---------------------------------------------------------------------------

-- Filesystem access sits behind these three fields so the unit tests can
-- drive the loader without a real filesystem — same dependency-injection
-- pattern as the crypto helpers above.

_M._read_file = function(path)
    local fh, oerr = io.open(path, "r")
    if not fh then return nil, tostring(oerr or "cannot open") end
    local content = fh:read("*a")
    fh:close()
    if not content then return nil, "unreadable (is it a directory?)" end
    return content
end

-- "file" | "directory" | nil
_M._path_kind = function(path)
    local ok, lfs = pcall(require, "lfs")
    if ok and type(lfs) == "table" and lfs.attributes then
        local mode = lfs.attributes(path, "mode")
        if mode == "directory" then return "directory" end
        if mode == "file" then return "file" end
        return nil
    end
    -- No luafilesystem (plain-Lua runs): probe by reading a byte. A directory
    -- handle opens but does not read on Linux.
    local fh = io.open(path, "r")
    if not fh then return nil end
    local probe = fh:read(1)
    fh:close()
    if probe == nil then return nil end
    return "file"
end

-- Regular `*.json` files in `path`, sorted by name — the sort IS the
-- evaluation order, which is why an operator can prefix files (00-, 10-)
-- to control it. Returns nil + err when the directory cannot be listed.
_M._list_dir = function(path)
    local ok, lfs = pcall(require, "lfs")
    if not (ok and type(lfs) == "table" and lfs.dir) then
        return nil, "luafilesystem unavailable"
    end
    local iter_ok, iterator, state = pcall(lfs.dir, path)
    if not iter_ok or not iterator then
        return nil, tostring(iterator or "cannot list")
    end
    local names = {}
    for entry in iterator, state do
        if entry ~= "." and entry ~= ".." and entry:match("%.json$")
           and lfs.attributes(path .. entry, "mode") == "file" then
            names[#names + 1] = entry
        end
    end
    table.sort(names)
    return names
end

-- Read the configured path into a pack. Returns nil + err when nothing
-- usable came out of it; a directory where SOME files are broken yields a
-- pack with the good ones plus one ERR line per bad file (fail-open,
-- granular, loud — see the header).
_M.load_file_pack = function(path)
    local kind = _M._path_kind(path)
    if not kind then
        return nil, "path not found or not readable: " .. tostring(path)
    end

    local sources = {}
    if kind == "directory" then
        local base = path:match("/$") and path or (path .. "/")
        local names, lerr = _M._list_dir(base)
        if not names then
            return nil, "cannot list directory " .. base .. ": " .. tostring(lerr)
        end
        if #names == 0 then
            return nil, "no *.json files in " .. base
        end
        for _, name in ipairs(names) do
            local content, rerr = _M._read_file(base .. name)
            if content then
                sources[#sources + 1] = { name = name, json = content }
            else
                kong.log.err("[karna] global rules: cannot read ", base, name,
                             " (", tostring(rerr), ") — file skipped")
            end
        end
        if #sources == 0 then
            return nil, "no readable *.json files in " .. base
        end
    else
        local content, rerr = _M._read_file(path)
        if not content then
            return nil, "cannot read " .. path .. ": " .. tostring(rerr)
        end
        sources[#sources + 1] = { name = path, json = content }
    end

    -- Fingerprint the exact bytes this pack was built from. It answers "are
    -- all my nodes running the same global rules?" and, unlike a hand-written
    -- version field, it cannot be forgotten on an edit.
    local blob = {}
    for _, source in ipairs(sources) do blob[#blob + 1] = source.json end
    local fingerprint = _M._sha256_hex(table.concat(blob, "\n"))
    local short = fingerprint and ("sha256:" .. fingerprint:sub(1, 12)) or nil

    local pack, errors = _M.build_sources(sources, short)
    for _, err in ipairs(errors) do
        kong.log.err("[karna] global rules: ", err, " — file skipped")
    end
    if #pack.all == 0 and #errors > 0 then
        return nil, errors[1]
    end

    pack.source = "file"
    pack.path = path
    pack.files = #sources
    pack.skipped_files = #errors
    pack.fingerprint = fingerprint
    return pack
end

_M._file_config = nil
_M.file_config = function()
    if _M._file_config ~= nil then return _M._file_config end

    local path = os.getenv("KARNA_GLOBAL_RULES_PATH")
    if not path or path == "" then
        _M._file_config = false  -- memoized "disabled"
        return false
    end

    _M._file_config = { path = path }
    return _M._file_config
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
        if _M._redis_pack and #_M._redis_pack.all > 0 then
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
    kong.log.notice("[karna] global rules: applied redis pack version ", fields.version,
                    " (", pack.n_json, " json + ", pack.n_seclang, " seclang rules: ",
                    pack.n_controls, " controls + ", pack.n_detection, " detection",
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

-- Called from handler.lua init_worker, once per worker. The two sources are
-- wired independently: the disk pack is read inline (file I/O needs no
-- cosockets, and reading it here means it is live before the first request),
-- the Redis half can only schedule timers — one immediate load plus the
-- recurring poll. Returns true when at least one source is configured.
_M.init = function(opts)
    opts = opts or {}
    _M._engine  = opts.engine or _M._engine
    _M._compile = opts.compile or _M._compile

    local enabled = false

    -- disk source
    local fconf = _M.file_config()
    if fconf then
        enabled = true
        local pack, ferr = _M.load_file_pack(fconf.path)
        if pack then
            _M._file_pack = pack
            _M.recombine()
            kong.log.notice("[karna] global rules: loaded file pack ",
                            pack.version or "(unfingerprinted)",
                            " from ", fconf.path,
                            " (", tostring(pack.files), " file(s)",
                            pack.skipped_files > 0
                              and (", " .. pack.skipped_files .. " skipped") or "",
                            ", ", pack.n_controls, " controls + ", pack.n_detection, " detection",
                            pack.n_dropped > 0 and (", " .. pack.n_dropped .. " rules dropped") or "",
                            ", worker ", ngx.worker.id() or "?", ")")
        else
            -- Fail-open: the node keeps serving with CRS + local rules (and
            -- the Redis pack, if any). Loud, because a baseline that silently
            -- did not load is worse than no baseline at all.
            kong.log.err("[karna] global rules: file pack NOT loaded from ",
                         fconf.path, " (", tostring(ferr), ") — no rules from disk")
        end
    else
        kong.log.debug("[karna] global rules: KARNA_GLOBAL_RULES_PATH not set — disk source off")
    end

    -- redis source
    local conf = _M.config()
    if conf then
        enabled = true

        local ok, err = ngx.timer.at(0, timer_tick)
        if not ok then
            kong.log.err("[karna] global rules: failed to schedule initial load: ", err)
        end
        local ok2, err2 = ngx.timer.every(conf.poll, timer_tick)
        if not ok2 then
            kong.log.err("[karna] global rules: failed to schedule poll timer: ", err2)
        end

        kong.log.notice("[karna] global rules: redis source enabled — ", conf.host, ":",
                        tostring(conf.port), (conf.ssl and " (tls)" or ""),
                        ", poll ", tostring(conf.poll), "s, ",
                        conf.hmac_key and "HMAC signature REQUIRED" or "UNSIGNED mode")
    else
        kong.log.debug("[karna] global rules: KARNA_REDIS_URL not set — redis source off")
    end

    return enabled
end

return _M
