-- ka_re2 — LuaJIT FFI binding for libka_re2 (Karna's RE2::Set multi-@rx matcher).
--
-- Direction B spike (see memory karna-re2-spike). The .so is built from
-- `src/libka_re2/ka_re2.cc` and installed by the dev image at
-- `/usr/local/lib/libka_re2.so` (overridable via KARNA_LIBKA_RE2_SO, mirroring
-- libinjection / ka_ac). RE2::Set compiles N @rx patterns into one automaton
-- and returns, per scanned value, the ids of ALL patterns that match in a
-- single linear pass — the engine uses that to gate which CRS rules run.
--
-- Usage (build once per worker at init_worker):
--   local ka_re2 = require "kong.plugins.karna.modules.ka_re2"
--   local h, err, id_map, rejected = ka_re2.build({ pat1, pat2, ... }, true)
--   -- id_map[i] = RE2 set-id of input pattern i (>=0), or false if RE2
--   --   rejected it (caller MUST fall that rule back to ngx.re.match).
--   -- Per request value:
--   local n = ka_re2.scan(h, value)          -- fills h's out-buffer
--   for k = 0, math.min(n, h.max_ids) - 1 do
--       local set_id = ka_re2.id_at(h, k)    -- a pattern that matched
--   end
--
-- The automaton is read-only after build; scans are single-threaded per worker.

local ffi     = require "ffi"
local ffi_new = ffi.new
local min     = math.min

ffi.cdef[[
typedef struct ka_re2_t ka_re2_t;

ka_re2_t* ka_re2_new(int dot_nl);
int       ka_re2_add(ka_re2_t*, const char* pattern, size_t pattern_len);
int       ka_re2_compile(ka_re2_t*);
int       ka_re2_match(ka_re2_t*, const char* text, size_t text_len, int* out_ids, int max_ids);
size_t    ka_re2_size(const ka_re2_t*);
void      ka_re2_free(ka_re2_t*);
]]

local _M = {}

local lib, loaded

local function _loadlib()
    if loaded then return lib ~= nil end
    local so = os.getenv("KARNA_LIBKA_RE2_SO") or "/usr/local/lib/libka_re2.so"
    local ok, l = pcall(ffi.load, so)
    if ok and l then
        lib = l
        loaded = true
        return true
    end
    loaded = true  -- don't keep retrying
    return false
end

-- True if the .so is available. Callers MUST check before .build() and fall
-- back to the pure-Lua @rx path when false (the spike is flag-gated AND
-- degrades gracefully when the lib is missing).
function _M.available()
    return _loadlib()
end

local Handle = {}
Handle.__index = Handle

-- build({pat1, pat2, ...}, dot_nl) -> handle, err, id_map, rejected
--   dot_nl   : true => '.' matches newline (Karna's 's' flag). Default true.
--   id_map   : array parallel to `patterns`; id_map[i] is the RE2 set-id
--              (>=0) assigned to patterns[i], or `false` if RE2 rejected it.
--              The caller maps set-id -> rule and, for `false`, leaves that
--              rule on the ngx.re.match path (no silent drop).
--   rejected : array of input indices RE2 refused (for logging coverage).
function _M.build(patterns, dot_nl)
    if not _loadlib() then
        return nil, "libka_re2.so not loadable"
    end
    if type(patterns) ~= "table" then
        return nil, "patterns must be a table"
    end
    if #patterns == 0 then
        return nil, "no patterns"
    end

    local raw = lib.ka_re2_new(dot_nl == false and 0 or 1)
    if raw == nil then
        return nil, "ka_re2_new returned NULL"
    end
    local re2 = ffi.gc(raw, lib.ka_re2_free)

    local id_map   = {}
    local rejected = {}
    for i = 1, #patterns do
        local p = patterns[i]
        if type(p) ~= "string" or #p == 0 then
            id_map[i] = false
            rejected[#rejected + 1] = i
        else
            local idx = lib.ka_re2_add(re2, p, #p)
            if idx >= 0 then
                id_map[i] = idx
            else
                id_map[i] = false
                rejected[#rejected + 1] = i
            end
        end
    end

    if lib.ka_re2_compile(re2) ~= 0 then
        return nil, "ka_re2_compile failed"
    end

    local n = tonumber(lib.ka_re2_size(re2))
    local cap = n > 0 and n or 1
    local h = setmetatable({
        _re2       = re2,
        n_patterns = n,
        max_ids    = cap,
        _out       = ffi_new("int[?]", cap),
    }, Handle)
    return h, nil, id_map, rejected
end

-- Scan `text`; fills the handle's out-buffer with matched set-ids (ascending).
-- Returns the TOTAL match count (may exceed h.max_ids — only the first
-- h.max_ids ids are readable via id_at; the buffer is sized to n_patterns so
-- that only happens if every pattern matched, which can't gate-skew anything).
function _M.scan(h, text)
    return lib.ka_re2_match(h._re2, text, #text, h._out, h.max_ids)
end

-- Read the k-th matched set-id (0-based) from the last scan's out-buffer.
function _M.id_at(h, k)
    return h._out[k]
end

-- Convenience for tests: return a set {set_id=true, ...} of all matches.
function _M.matched_set(h, text)
    local n = _M.scan(h, text)
    local out = {}
    for k = 0, min(n, h.max_ids) - 1 do
        out[h._out[k]] = true
    end
    return out
end

return _M
