local t = {}
t[1] = nil
t[2] = nil
local m, err = ngx.re.match("multipart/form-data; boundary=xxx",[[;\s*boundary\s*=\s*(?:"([^"]+)"|([-|+*$&!.%'`~^\#\w]+))]], "joi", nil, t)

print(t[1])
print(t[2])

if m then
    print("Match 0: ", m[0])
    print("Match 1: ", m[1])
end
if err then
    print("error: ", err)
end