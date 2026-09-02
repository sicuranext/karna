-- ka-unittest/tls_telemetry.lua
--
-- Tests for ka_tls: negotiated TLS block, pseudonymous connection id, rule
-- variable resolution, inspection rows and audit blocks. Plain assertions, no
-- luaunit, no ngx. Run from repo root:   lua ka-unittest/tls_telemetry.lua

package.path = "./kong/plugins/karna/modules/?.lua;" .. package.path

local ok, tls = pcall(require, "ka_tls")
if not ok then
    io.stderr:write("FAIL: cannot load ka_tls.lua: " .. tostring(tls) .. "\n")
    os.exit(1)
end

local failures = 0
local function check(label, cond)
    if cond then print("  PASS  " .. label) else print("  FAIL  " .. label); failures = failures + 1 end
end

-- Deterministic stand-ins for the OpenResty primitives -----------------------
local hmac_calls = 0
local function fake_hmac(key, msg)                 -- 32 bytes, deterministic, input-sensitive
    hmac_calls = hmac_calls + 1
    local s = key .. "\0" .. msg
    local out = {}
    for i = 1, 32 do
        local h = 2166136261 + i
        for j = 1, #s do h = (h * 31 + s:byte(j) * (i + j)) % 4294967291 end   -- no bitwise ops: LuaJIT/5.1 compatible
        out[i] = string.char(h % 256)
    end
    return table.concat(out)
end
local function fake_random(seed) return function(n) return string.rep(string.char(seed), n) end end
local function fake_cache()
    local store = {}
    return { get = function(_, k) return store[k] end, set = function(_, k, v) store[k] = v end }
end
local warnings = {}
local function warn(m) warnings[#warnings + 1] = m end

-- Measured on Kong 3.9 / openresty 1.25.3.2 (dev + production) ------------------
local V13 = { ssl_protocol = "TLSv1.3", ssl_cipher = "TLS_AES_128_GCM_SHA256", ssl_curve = "X25519",
              ssl_alpn_protocol = "h2", ssl_server_name = "example.com", ssl_session_reused = ".",
              ssl_early_data = "", connection = "6599",
              ssl_ciphers = "0x9a9a:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256",
              ssl_curves  = "0xbaba:0x11ec:X25519:prime256v1:secp384r1" }
local V12_RESUMED = { ssl_protocol = "TLSv1.2", ssl_cipher = "ECDHE-RSA-AES256-GCM-SHA384", ssl_curve = "X25519",
              ssl_alpn_protocol = "", ssl_server_name = "example.com", ssl_session_reused = "r",
              ssl_early_data = "", connection = "6579",
              ssl_ciphers = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384", ssl_curves = "" }
local PLAIN = { ssl_protocol = "", connection = "6545", server_protocol = "HTTP/1.1" }

-- collect ------------------------------------------------------------------------
print("collect")
local t = tls.collect(V13)
check("TLS 1.3: enabled", t.enabled == true)
check("TLS 1.3: complete", t.capture_status == "complete")
check("TLS 1.3: scalars copied", t.protocol == "TLSv1.3" and t.cipher == "TLS_AES_128_GCM_SHA256"
      and t.curve == "X25519" and t.alpn == "h2" and t.sni == "example.com")
check("TLS 1.3: booleans from '.' and ''", t.session_reused == false and t.early_data == false)
check("TLS 1.3: client lists kept verbatim (order, GREASE, hex unknowns)",
      t.client_ciphers == V13.ssl_ciphers and t.client_curves == V13.ssl_curves)

t = tls.collect(V12_RESUMED)
check("TLS 1.2 resumed: session_reused true from 'r'", t.session_reused == true)
check("TLS 1.2 resumed: empty curves do NOT make it partial", t.capture_status == "complete" and t.client_curves == "")
check("TLS 1.2 resumed: empty alpn kept as empty string", t.alpn == "")

t = tls.collect(PLAIN)
check("plain HTTP: enabled false, not_tls, nothing else", t.enabled == false and t.capture_status == "not_tls"
      and t.protocol == nil and t.cipher == nil and t.client_ciphers == nil)

t = tls.collect({ connection = "1" })
check("missing ssl_protocol (nil) → not_tls", t.capture_status == "not_tls")

t = tls.collect({ ssl_protocol = "TLSv1.3", ssl_cipher = "", ssl_ciphers = "A:B" })
check("empty negotiated cipher → partial", t.capture_status == "partial")
t = tls.collect({ ssl_protocol = "TLSv1.3", ssl_cipher = "X", ssl_ciphers = "" })
check("empty client cipher list → partial", t.capture_status == "partial")
t = tls.collect({ ssl_protocol = "TLSv1.3", ssl_cipher = "X", ssl_ciphers = "A", ssl_early_data = "1" })
check("early_data '1' → true", t.early_data == true)
t = tls.collect({ ssl_protocol = "TLSv1.3", ssl_cipher = "X", ssl_ciphers = "A", ssl_curve = 42 })
check("non-string variable value → empty string", t.curve == "")

local huge = string.rep("ECDHE-RSA-AES128-GCM-SHA256:", 400)
t = tls.collect({ ssl_protocol = "TLSv1.3", ssl_cipher = "X", ssl_ciphers = huge, ssl_curves = huge })
check("client lists clipped to MAX_LIST_LEN", #t.client_ciphers == tls.MAX_LIST_LEN and #t.client_curves == tls.MAX_LIST_LEN)
t = tls.collect({ ssl_protocol = "TLSv1.3", ssl_cipher = "X", ssl_ciphers = huge }, 10)
check("custom cap honoured", #t.client_ciphers == 10)

t = tls.collect(nil)
check("nil var table → error status, no throw", t.enabled == false and t.capture_status == "error")

-- connection_id ----------------------------------------------------------------------
print("connection_id")
check("before init → nil", tls.connection_id(V13) == nil)

local st = tls.init({ env_key = "0123456789abcdef0123456789abcdef", worker_id = 0,
                      random_bytes = fake_random(1), hmac = fake_hmac, cache = fake_cache(), warn = warn })
check("env key of 32 bytes is used", st.key_source == "env" and st.key == "0123456789abcdef0123456789abcdef")
check("no warning with a good key", #warnings == 0)
check("nonce is hex of 16 random bytes", #st.nonce == 32 and st.nonce:match("^%x+$") ~= nil)

local id1 = tls.connection_id(V13)
check("format kc1_ + 32 hex", id1 ~= nil and id1:match("^kc1_%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x$") ~= nil)
check("same connection → same id", tls.connection_id(V13) == id1)
check("second call served from cache (hmac not recomputed)", hmac_calls == 1)
local id2 = tls.connection_id(V12_RESUMED)
check("different connection → different id", id2 ~= nil and id2 ~= id1)
check("id does not contain the connection serial or the nonce", not id1:find("6599", 1, true) and not id1:find(st.nonce, 1, true))
check("no connection serial → nil", tls.connection_id({ ssl_protocol = "TLSv1.3" }) == nil and tls.connection_id(nil) == nil)
check("plain HTTP still gets an id", tls.connection_id(PLAIN) ~= nil)

-- same key, different worker → different id for the same serial (isolation)
tls.init({ env_key = "0123456789abcdef0123456789abcdef", worker_id = 1,
           random_bytes = fake_random(1), hmac = fake_hmac, cache = fake_cache(), warn = warn })
check("same key + serial, other worker → different id", tls.connection_id(V13) ~= id1)
-- same key + worker, different nonce (another instance / restart) → different id
tls.init({ env_key = "0123456789abcdef0123456789abcdef", worker_id = 0,
           random_bytes = fake_random(2), hmac = fake_hmac, cache = fake_cache(), warn = warn })
check("same key + worker + serial, other nonce → different id", tls.connection_id(V13) ~= id1)
-- same everything → same id (determinism of the construction)
tls.init({ env_key = "0123456789abcdef0123456789abcdef", worker_id = 0,
           random_bytes = fake_random(1), hmac = fake_hmac, cache = fake_cache(), warn = warn })
check("same key + worker + nonce + serial → same id", tls.connection_id(V13) == id1)
-- other key → different id
tls.init({ env_key = "ffffffffffffffffffffffffffffffff", worker_id = 0,
           random_bytes = fake_random(1), hmac = fake_hmac, cache = fake_cache(), warn = warn })
check("other key → different id", tls.connection_id(V13) ~= id1)

warnings = {}
st = tls.init({ env_key = false, worker_id = 0, random_bytes = fake_random(7), hmac = fake_hmac, cache = fake_cache(), warn = warn })
check("no env key → random key + one warning", st.key_source == "random" and #st.key == 32 and #warnings == 1)
check("random-key mode still yields well-formed ids", (tls.connection_id(V13) or ""):match("^kc1_%x+$") ~= nil)
warnings = {}
st = tls.init({ env_key = "short", worker_id = 0, random_bytes = fake_random(7), hmac = fake_hmac, cache = fake_cache(), warn = warn })
check("key shorter than 16 bytes → ignored, random, warning mentions it", st.key_source == "random" and #warnings == 1 and warnings[1]:find("shorter") ~= nil)

tls.init({ env_key = false, worker_id = 0, random_bytes = fake_random(7), cache = fake_cache(), warn = warn,
           hmac = function() return nil end })
check("hmac failure → nil id, no throw", tls.connection_id(V13) == nil)
tls.init({ env_key = false, worker_id = 0, random_bytes = fake_random(7), cache = fake_cache(), warn = warn,
           hmac = function() return "short" end })
check("hmac too short → nil id", tls.connection_id(V13) == nil)

-- populate / resolve_variable / inspection / audit ---------------------------------------
print("populate + resolve_variable")
tls.init({ env_key = "0123456789abcdef0123456789abcdef", worker_id = 0,
           random_bytes = fake_random(1), hmac = fake_hmac, cache = fake_cache(), warn = warn })
local ctx = {}
tls.populate(ctx, V13)
check("populate fills ctx.tls and ctx.connection_id", ctx.tls and ctx.tls.enabled == true and ctx.connection_id == id1)
local before = ctx.tls
tls.populate(ctx, PLAIN)
check("populate is idempotent per request", ctx.tls == before)

check("connection.id", tls.resolve_variable("connection.id", ctx) == id1)
check("tls.enabled → 'true'", tls.resolve_variable("tls.enabled", ctx) == "true")
check("tls.capture_status", tls.resolve_variable("tls.capture_status", ctx) == "complete")
check("tls.protocol / cipher / curve / alpn / sni", tls.resolve_variable("tls.protocol", ctx) == "TLSv1.3"
      and tls.resolve_variable("tls.cipher", ctx) == "TLS_AES_128_GCM_SHA256"
      and tls.resolve_variable("tls.curve", ctx) == "X25519"
      and tls.resolve_variable("tls.alpn", ctx) == "h2"
      and tls.resolve_variable("tls.sni", ctx) == "example.com")
check("booleans as 'true'/'false' strings", tls.resolve_variable("tls.session_reused", ctx) == "false"
      and tls.resolve_variable("tls.early_data", ctx) == "false")
check("lists as colon strings", tls.resolve_variable("tls.client_ciphers", ctx) == V13.ssl_ciphers
      and tls.resolve_variable("tls.client_curves", ctx) == V13.ssl_curves)
check("unknown tls field → nil", tls.resolve_variable("tls.fingerprint", ctx) == nil and tls.resolve_variable("tls.", ctx) == nil)
check("internal state not reachable as a variable", tls.resolve_variable("tls.key", ctx) == nil)

local pctx = {}
tls.populate(pctx, PLAIN)
check("plain: tls.enabled 'false', capture_status 'not_tls'", tls.resolve_variable("tls.enabled", pctx) == "false"
      and tls.resolve_variable("tls.capture_status", pctx) == "not_tls")
check("plain: other tls.* absent (nil), so isSet is false", tls.resolve_variable("tls.protocol", pctx) == nil
      and tls.resolve_variable("tls.client_ciphers", pctx) == nil)
check("plain: connection.id present", tls.resolve_variable("connection.id", pctx) ~= nil)

local rctx = {}
tls.populate(rctx, V12_RESUMED)
check("empty list resolves to '' (present), distinct from absent", tls.resolve_variable("tls.client_curves", rctx) == ""
      and tls.resolve_variable("tls.session_reused", rctx) == "true")

check("unpopulated ctx → nil", tls.resolve_variable("tls.enabled", {}) == nil and tls.resolve_variable("connection.id", {}) == nil)
check("nil ctx → nil, no throw", tls.resolve_variable("tls.enabled", nil) == nil)

print("inspection table")
local rows = {}
tls.populate_inspection_table(rows, ctx)
local flat = {}
for _, r in ipairs(rows) do for k, v in pairs(r) do flat[k] = v end end
check("rows: connection.id + enabled + status + 9 fields", #rows == 12 and flat["connection.id"] == id1
      and flat["tls.enabled"] == "true" and flat["tls.sni"] == "example.com" and flat["tls.session_reused"] == "false")
rows = {}
tls.populate_inspection_table(rows, pctx)
check("plain rows: connection.id + enabled + status only", #rows == 3 and flat["tls.enabled"] ~= nil)
tls.populate_inspection_table(nil, ctx)
check("nil table → no throw", true)

print("audit blocks")
local network, block = tls.audit_blocks(ctx)
check("network.connection_id", network and network.connection_id == id1)
check("tls block: booleans stay booleans", block.enabled == true and block.session_reused == false and block.early_data == false)
check("tls block: 11 keys", (function() local n = 0; for _ in pairs(block) do n = n + 1 end; return n end)() == 11)
check("tls block: lists as strings", block.client_ciphers == V13.ssl_ciphers)
network, block = tls.audit_blocks(pctx)
check("plain: tls = {enabled=false, capture_status='not_tls'} only",
      block.enabled == false and block.capture_status == "not_tls" and block.protocol == nil
      and (function() local n = 0; for _ in pairs(block) do n = n + 1 end; return n end)() == 2)
check("plain: network still present", network and network.connection_id ~= nil)
network, block = tls.audit_blocks({})
check("unpopulated ctx → nil, nil", network == nil and block == nil)
network, block = tls.audit_blocks({ tls = { enabled = false, capture_status = "not_tls" } })
check("no connection id → network nil, tls kept", network == nil and block.capture_status == "not_tls")

check("to_hex", tls._to_hex("\0\255\16") == "00ff10")

if failures > 0 then
    io.stderr:write(("\n%d failure(s)\n"):format(failures))
    os.exit(1)
end
print("\nall green")
