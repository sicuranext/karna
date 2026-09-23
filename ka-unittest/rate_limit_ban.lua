-- Drive the real handler behind minimal Kong stubs, then execute the
-- actual Redis script against a small clocked fixture. No network required.
for _,name in ipairs({'ka_engine','ka_body_parser','ka_utils','ka_seclang','ka_mcp',
    'ka_compile','ka_global_rules','ka_re2_gate','ka_header_names','ka_tls','ka_redact'}) do
    package.preload['kong.plugins.karna.'..name]=function() return {} end
end
package.preload['kong.plugins.karna.version']=function() return {version='test'} end
package.preload['resty.lrucache']=function() return {new=function() return {get=function() end,set=function() end} end} end
package.preload['resty.ipmatcher']=function() return {} end
package.preload['cjson']=function() return {} end
ngx={var={},worker={id=function() return 0 end}}
kong={ctx={plugin={},shared={}},log={err=function() end,debug=function() end,warn=function() end},
      response={exit=function() end,set_header=function() end}}
local engine = require 'kong.plugins.karna.ka_engine'
local utils = require 'kong.plugins.karna.ka_utils'
local handler = dofile('kong/plugins/karna/handler.lua')
local calls, current, outcome
ngx.var = {remote_addr='203.0.113.9'}
kong.request = {get_host=function() return 'example.test' end}
engine.loop_rules = function() return true, current, {} end
utils.redis_incr_key = function(_, key, window) calls.normal={key,window}; return outcome end
utils.redis_incr_key_with_ban = function(_, key, window, ban_key, limit, seconds)
    calls.ban={key,window,ban_key,limit,seconds}; return outcome, outcome ~= nil and outcome > limit, outcome ~= nil and outcome > limit and seconds or 0
end
utils.build_block_response = function() return 'limited', {} end
local function run(ban, blocking, controls, count)
    calls={}; outcome=count
    kong.ctx.plugin={ka_matched_rules={},rule_controls=controls}
    current={id='login',action={rate_limit={key='%{remote_addr}',limit=50,window_seconds=21600,ban=ban}}}
    handler._internals.evaluate_rules({__plugin_id='service-a',engine_blocking_mode=blocking}, {}, 'access')
    return kong.ctx.plugin.ka_matched_rules[1]
end
local policy={key='%{remote_addr}',duration_seconds=1200}
local m=run(policy,true,nil,50)
assert(calls.ban and not m.rate_limited and not m.rate_limit_ban_created)
assert(calls.ban[1]=='karna:rl:service-a:login:203.0.113.9')
assert(calls.ban[3]=='karna:ban:service-a:203.0.113.9')
m=run(policy,true,nil,51); assert(m.rate_limited and m.rate_limit_ban_created and m.rate_limit_ban_ttl==1200)
run(policy,false,nil,51); assert(calls.normal and not calls.ban)
run(policy,true,{detection_only=true},51); assert(calls.normal and not calls.ban)
run(policy,false,{engine_on=true},51); assert(calls.ban)
run(nil,true,nil,51); assert(calls.normal and not calls.ban)
for _,value in ipairs({0,-1,1.5,86401,'invalid',math.huge}) do
    run({key='%{remote_addr}',duration_seconds=value},true,nil,51)
    assert(calls.normal and not calls.ban)
end
run({key='',duration_seconds=1200},true,nil,51); assert(calls.normal)
run(policy,true,nil,nil); assert(not kong.ctx.plugin.ka_matched_rules[1].rate_limited)
print('handler ban policy: passed')

package.preload['inspect']=function() return function() return '' end end
kong.request.get_header=function() end
kong.request.get_headers=function() return {} end
kong.request.get_path_with_query=function() return '/' end
kong.request.get_method=function() return 'GET' end
kong.request.get_http_version=function() return 1.1 end
kong.service={response={get_headers=function() return {} end,get_status=function() return 200 end}}
kong.response.get_status=function() return 200 end
ngx.re={match=function() end}
local real_utils=dofile('kong/plugins/karna/modules/ka_utils.lua')
local now, store, fail = 0, {}, false
local function slot(key)
    local v=store[key]
    if v and v.deadline and v.deadline<=now then store[key]=nil; v=nil end
    return v
end
local function command(op,key,a,b,c,d)
    local v=slot(key)
    if op=='INCR' then
        v=v or {value=0}; v.value=v.value+1; store[key]=v; return v.value
    elseif op=='TTL' then return not v and -2 or (v.deadline and math.ceil(v.deadline-now) or -1)
    elseif op=='EXPIRE' then assert(v); v.deadline=now+tonumber(a); return 1
    elseif op=='SET' then
        assert(b=='EX' and d=='NX')
        if v then return false end
        store[key]={value=a,deadline=now+tonumber(c)}; return 'OK'
    else error('unexpected command '..op) end
end
local red={close=function() end,set_keepalive=function() return true end,
    set_timeouts=function() end,connect=function() return true end,
    select=function(_,db) assert(db==0); return true end}
function red:eval(script,nkeys,...)
    if fail then return nil,'synthetic Redis error' end
    local args={...}; local keys,argv={},{}
    for i=1,nkeys do keys[i]=args[i] end
    for i=nkeys+1,#args do argv[#argv+1]=args[i] end
    local env={redis={call=command},KEYS=keys,ARGV=argv,tonumber=tonumber}
    local fn
    if _VERSION=='Lua 5.1' then fn=assert(loadstring(script));setfenv(fn,env)
    else fn=assert(load(script,'redis-script','t',env)) end
    return fn()
end
package.preload['resty.redis']=function() return {new=function() return red end} end
local function incr(key,ban) return real_utils:redis_incr_key_with_ban(key,21600,ban,50,1200) end
for i=1,50 do local n,created,ttl=incr('counter-a','ban-a');assert(n==i and not created and ttl==0) end
assert(not slot('ban-a'))
local n,created,ttl=incr('counter-a','ban-a');assert(n==51 and created and ttl==1200)
local deadline=store['ban-a'].deadline
now=90
n,created,ttl=incr('counter-a','ban-a');assert(n==52 and not created and ttl==1110)
assert(store['ban-a'].deadline==deadline and store['counter-a'].deadline==21600)
local other=incr('counter-b','ban-b');assert(other==1 and not slot('ban-b'))
now=1200
assert(not slot('ban-a'))
n,created,ttl=incr('counter-a','ban-a');assert(n==53 and created and ttl==1200)
now=21600
n,created,ttl=incr('counter-a','ban-a');assert(n==1 and not created and ttl==0)
fail=true;assert(incr('counter-a','ban-a')==nil)
local entry={rate_limit_key='counter-a',rate_limit_count=51,rate_limit_limit=50,rate_limit_window=21600,
             rate_limit_ban_key='ban-a',rate_limit_ban_created=true,rate_limit_ban_ttl=1200}
local fields=real_utils:build_rate_limit_fields(entry)
assert(fields.rate_limit_ban_created and fields.rate_limit_ban_ttl==1200)
assert(real_utils:build_v1_rate_limit_data(entry):find('ban_created=true ban_ttl=1200',1,true))
print('atomic ban script, deadlines, scope, reban, failure, audit: passed')
