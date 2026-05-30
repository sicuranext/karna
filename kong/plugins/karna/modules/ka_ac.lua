-- ka_ac — LuaJIT FFI binding for libka_ac (Karna's Aho-Corasick prefilter).
--
-- The .so is built from `src/libka_ac/ka_ac.c` and installed by the dev image
-- at `/usr/local/lib/libka_ac.so`. The path is overridable for tests via the
-- `KARNA_LIBKA_AC_SO` env var (mirroring how libinjection is wired —
-- see [[bench-log-level]] for the env-propagation requirement in nginx).
--
-- Usage:
--   local ka_ac = require "kong.plugins.karna.modules.ka_ac"
--   local ac = ka_ac.build({ "union", "select", "script" })   -- build once
--   local bm = ka_ac.new_bitmap(ac)
--   ka_ac.scan(ac, "1 UNION SELECT", bm)                       -- per-value
--   if ka_ac.bit_test(bm, 0) then ... end                      -- check pattern 0
--   ka_ac.bitmap_clear(bm)                                     -- reuse buffer
--
-- The automaton is read-only after build; the same `ac` can be scanned
-- concurrently. Build is one-shot per worker at init_worker.

local ffi     = require "ffi"
local bit     = require "bit"
local ffi_new = ffi.new

ffi.cdef[[
typedef struct ka_ac_t ka_ac_t;

ka_ac_t* ka_ac_build(const char** patterns, const size_t* pattern_lens, size_t n_patterns);
void     ka_ac_free(ka_ac_t*);
int      ka_ac_scan(const ka_ac_t*, const char* text, size_t text_len, uint8_t* out_bitmap);
int      ka_ac_match_any(const ka_ac_t*, const char* text, size_t text_len);
size_t   ka_ac_n_patterns(const ka_ac_t*);
size_t   ka_ac_memory_bytes(const ka_ac_t*);
]]

local _M = {}

local lib, loaded

local function _loadlib()
    if loaded then return lib ~= nil end
    local so = os.getenv("KARNA_LIBKA_AC_SO") or "/usr/local/lib/libka_ac.so"
    local ok, l = pcall(ffi.load, so)
    if ok and l then
        lib = l
        loaded = true
        return true
    end
    loaded = true  -- don't keep retrying
    return false
end

-- True if the .so is available. Callers should check before .build().
function _M.available()
    return _loadlib()
end

-- Holds (a) the cdata ka_ac_t* with a __gc tied to ka_ac_free, (b) the
-- pattern count + bitmap byte-size used for the bitmap helpers, and (c) a
-- strong reference to the original pattern strings — Lua MUST keep these
-- alive while the automaton is in use because the C side only references
-- their bytes during build, but we keep them anyway for debugging.
local Handle = {}
Handle.__index = Handle

local function _bitmap_bytes(n)
    return math.floor((n + 7) / 8)
end

-- build({pat1, pat2, ...}) -> handle, err
-- Each pattern must be a non-empty Lua string.
function _M.build(patterns)
    if not _loadlib() then
        return nil, "libka_ac.so not loadable"
    end
    if type(patterns) ~= "table" then
        return nil, "patterns must be a table"
    end
    local n = #patterns
    if n == 0 then return nil, "no patterns" end

    local cstrs = ffi_new("const char*[?]", n)
    local clens = ffi_new("size_t[?]", n)
    for i = 1, n do
        local s = patterns[i]
        if type(s) ~= "string" or #s == 0 then
            return nil, "pattern " .. i .. " must be a non-empty string"
        end
        cstrs[i-1] = s
        clens[i-1] = #s
    end

    local raw = lib.ka_ac_build(cstrs, clens, n)
    if raw == nil then
        return nil, "ka_ac_build returned NULL (allocation or empty pattern)"
    end

    -- Tie the C lifetime to Lua GC.
    local ac = ffi.gc(raw, lib.ka_ac_free)

    local h = setmetatable({
        _ac           = ac,
        _patterns     = patterns,  -- keep alive for introspection / debugging
        n_patterns    = n,
        bitmap_bytes  = _bitmap_bytes(n),
    }, Handle)
    return h
end

-- Allocate a zeroed bitmap (uint8_t[N]) sized for the handle's pattern count.
function _M.new_bitmap(h)
    return ffi_new("uint8_t[?]", h.bitmap_bytes)
end

-- Zero a bitmap so it can be reused for the next value.
function _M.bitmap_clear(bm, h)
    ffi.fill(bm, h.bitmap_bytes, 0)
end

-- Scan `text` (Lua string) and OR the matched-pattern bits into `bm`.
-- The bitmap is NOT zeroed by scan — caller is expected to either clear it
-- between values or accumulate matches across multiple values.
function _M.scan(h, text, bm)
    return lib.ka_ac_scan(h._ac, text, #text, bm)
end

-- Boolean multi-pattern membership: true iff ANY pattern occurs in `text`
-- (case-insensitive). Early-exits, no bitmap. This is the @pm / @pmFromFile
-- replacement — one linear pass instead of N Lua string.find calls.
function _M.match_any(h, text)
    return lib.ka_ac_match_any(h._ac, text, #text) == 1
end

-- Test bit `pid` (0-based) in bitmap `bm`. Returns true/false.
local band = bit.band
local rshift = bit.rshift
function _M.bit_test(bm, pid)
    return band(bm[rshift(pid, 3)], bit.lshift(1, band(pid, 7))) ~= 0
end

-- Diagnostic: number of patterns + memory used by the automaton.
function _M.info(h)
    return {
        n_patterns   = tonumber(lib.ka_ac_n_patterns(h._ac)),
        memory_bytes = tonumber(lib.ka_ac_memory_bytes(h._ac)),
    }
end

return _M
