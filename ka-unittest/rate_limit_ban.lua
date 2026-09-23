-- A configured rate-limit ban is created and enforced by one rule, across all
-- paths of its routed service, without affecting another service.
local active_rule = {
    id = 'login', phase = 'access',
    action = {rate_limit = {
        key = '%{remote_addr}', limit = 2, window_seconds = 60,
        ban = {key = '%{remote_addr}', after_exceedances = 2, duration_seconds = 20},
    }},
}

local engine, utils = {}, {}
for _, name in ipairs({'ka_body_parser','ka_seclang','ka_mcp','ka_re2_gate',
    'ka_header_names','ka_tls','ka_redact'}) do
    package.preload['kong.plugins.karna.' .. name] = function() return {} end
end
package.preload['kong.plugins.karna.ka_engine'] = function() return engine end
package.preload['kong.plugins.karna.ka_utils'] = function() return utils end
package.preload['kong.plugins.karna.ka_compile'] = function()
    return {compile_rules = function() end}
end
package.preload['kong.plugins.karna.ka_global_rules'] = function()
    return {get = function() end}
end
package.preload['kong.plugins.karna.version'] = function() return {version = 'test'} end
package.preload['resty.ipmatcher'] = function() return {new = function() return {match = function() end} end} end
package.preload['resty.lrucache'] = function()
    return {new = function()
        local data = {}
        return {get = function(_, k) return data[k] end, set = function(_, k, v) data[k] = v end}
    end}
end
package.preload['cjson'] = function()
    return {decode = function() return active_rule end, encode = function() return '{}' end}
end

ngx = {var = {remote_addr = '203.0.113.9'}, worker = {id = function() return 0 end}}
local service_id, path, response, cache_hit = 'service-a', '/login', nil, false
kong = {
    ctx = {plugin = {}, shared = {}},
    log = {err = function() end, debug = function() end, warn = function() end, inspect = function() end},
    router = {get_service = function() return {id = service_id} end},
    request = {
        get_host = function() return 'example.test' end,
        get_method = function() return 'GET' end,
        get_scheme = function() return 'https' end,
        get_path = function() return path end,
        get_header = function() end,
    },
    response = {
        set_header = function() end,
        exit = function(status, body, headers)
            response = {status = status, body = body, headers = headers}
            error('__EXIT__', 0)
        end,
    },
}

for _, method in ipairs({'method_allowed','uri_path_check_violation',
    'check_request_headers_allowed','check_request_content_type_charset',
    'check_request_content_type_enforce','check_request_body_parser'}) do
    engine[method] = function() end
end
engine.check_request_arg_count = function() return false end
engine.loop_rules = function(_, _, rules)
    if rules and #rules > 0 then return true, rules[1], {} end
    return false
end

local counts, bans, last_counter_key, last_ban_key = {}, {}, nil, nil
utils.redis_first_active_ban = function(_, keys)
    for i, key in ipairs(keys) do if bans[key] then return i, bans[key] end end
end
utils.redis_incr_key = function(_, key)
    counts[key] = (counts[key] or 0) + 1
    return counts[key]
end
utils.redis_incr_key_with_ban = function(_, key, _, ban_key, limit, seconds, excess)
    last_counter_key, last_ban_key = key, ban_key
    if bans[ban_key] then return 0, false, bans[ban_key], true end
    counts[key] = (counts[key] or 0) + 1
    local count = counts[key]
    if count >= limit + excess then
        bans[ban_key], counts[key] = seconds, nil
        return count, true, seconds, true
    end
    return count, false, 0, false
end
utils.build_block_response = function(_, _, _, fallback) return fallback, {} end

local handler = dofile('kong/plugins/karna/handler.lua')
local conf = {
    __plugin_id = 'plugin-a', __seq__ = 1, engine_blocking_mode = true,
    rules_request = {'rule'}, local_rules_enabled = true, coreruleset_enabled = false,
    redis_host = 'redis', redis_port = 6379,
}
local last_match
local function run()
    response = nil
    kong.ctx.plugin, kong.ctx.shared = {}, {response_from_cache = cache_hit}
    local ok, err = pcall(handler.access, handler, conf)
    if not ok then assert(tostring(err):find('__EXIT__', 1, true)) end
    last_match = kong.ctx.plugin.ka_matched_rules and kong.ctx.plugin.ka_matched_rules[1]
    return response
end

assert(run() == nil)
assert(run() == nil)
assert(run().status == 429)
local triggered = run()
assert(triggered.status == 403 and triggered.headers['Retry-After'] == '20')
assert(last_match.rate_limit_ban_created and last_match.rate_limit_count == 4)
assert(last_counter_key == 'karna:rl:plugin-a:service-a:login:203.0.113.9')
assert(last_ban_key == 'karna:ban:plugin-a:service-a:login:203.0.113.9')

path, cache_hit = '/other', true
assert(run().status == 403)

service_id, cache_hit = 'service-b', false
assert(run() == nil)
assert(last_ban_key == 'karna:ban:plugin-a:service-b:login:203.0.113.9')

service_id, conf.engine_blocking_mode = 'service-c', false
assert(run() == nil and run() == nil and run() == nil and run() == nil)
assert(not bans['karna:ban:plugin-a:service-c:login:203.0.113.9'])
print('integrated ban enforcement and service isolation: passed')

-- Execute the real Redis scripts against a clocked in-memory Redis fixture.
package.preload['inspect'] = function() return function() return '' end end
kong.request.get_headers = function() return {} end
kong.request.get_path_with_query = function() return '/' end
kong.request.get_http_version = function() return 1.1 end
kong.service = {response = {get_headers = function() return {} end, get_status = function() return 200 end}}
kong.response.get_status = function() return 200 end
ngx.re = {match = function() end}

local now, store, fail = 0, {}, false
local function slot(key)
    local value = store[key]
    if value and value.deadline and value.deadline <= now then store[key] = nil; value = nil end
    return value
end
local function command(op, key, a, b, c, d)
    local value = slot(key)
    if op == 'EXISTS' then return value and 1 or 0
    elseif op == 'INCR' then
        value = value or {value = 0}; value.value = value.value + 1; store[key] = value; return value.value
    elseif op == 'TTL' then return not value and -2 or (value.deadline and math.ceil(value.deadline - now) or -1)
    elseif op == 'EXPIRE' then assert(value); value.deadline = now + tonumber(a); return 1
    elseif op == 'SET' then
        assert(b == 'EX' and d == 'NX')
        if value then return false end
        store[key] = {value = a, deadline = now + tonumber(c)}; return 'OK'
    elseif op == 'DEL' then store[key] = nil; return value and 1 or 0
    else error('unexpected command ' .. op) end
end
local red = {
    close = function() end, set_keepalive = function() return true end,
    set_timeouts = function() end, connect = function() return true end,
    select = function(_, db) assert(db == 0); return true end,
}
function red:eval(script, nkeys, ...)
    if fail then return nil, 'synthetic Redis error' end
    local args, keys, argv = {...}, {}, {}
    for i = 1, nkeys do keys[i] = args[i] end
    for i = nkeys + 1, #args do argv[#argv + 1] = args[i] end
    local env = {redis = {call = command}, KEYS = keys, ARGV = argv,
                 tonumber = tonumber, ipairs = ipairs}
    local fn
    if _VERSION == 'Lua 5.1' then fn = assert(loadstring(script)); setfenv(fn, env)
    else fn = assert(load(script, 'redis-script', 't', env)) end
    return fn()
end
package.preload['resty.redis'] = function() return {new = function() return red end} end
local real_utils = dofile('kong/plugins/karna/modules/ka_utils.lua')
local function incr(counter, ban)
    return real_utils:redis_incr_key_with_ban(counter, 21600, ban, 50, 1200, 10)
end
for i = 1, 50 do
    local count, created, ttl, active = incr('counter-a', 'ban-a')
    assert(count == i and not created and ttl == 0 and not active)
end
for i = 51, 59 do
    local count, created, ttl, active = incr('counter-a', 'ban-a')
    assert(count == i and not created and ttl == 0 and not active)
end
local count, created, ttl, active = incr('counter-a', 'ban-a')
assert(count == 60 and created and ttl == 1200 and active)
assert(not slot('counter-a'))
local deadline = store['ban-a'].deadline
now = 90
count, created, ttl, active = incr('counter-a', 'ban-a')
assert(count == 0 and not created and ttl == 1110 and active)
assert(store['ban-a'].deadline == deadline)
local index, remaining = real_utils:redis_first_active_ban({'ban-b', 'ban-a'})
assert(index == 2 and remaining == 1110)
now = 1200
count, created, ttl, active = incr('counter-a', 'ban-a')
assert(count == 1 and not created and ttl == 0 and not active)
fail = true
assert(incr('counter-a', 'ban-a') == nil)
local fields = real_utils:build_rate_limit_fields({
    rate_limit_key = 'counter-a', rate_limit_count = 60, rate_limit_limit = 50,
    rate_limit_window = 21600, rate_limit_ban_key = 'ban-a',
    rate_limit_ban_created = true, rate_limit_ban_ttl = 1200,
})
assert(fields.rate_limit_ban_created and fields.rate_limit_ban_ttl == 1200)
print('atomic threshold, fixed deadline, reset and lookup: passed')
