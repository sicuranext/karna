package.path = './kong/plugins/karna/?.lua;' .. package.path
local inspect = require "inspect"

local m = ngx.re.match(
    "exec\t/*foo\r\nbar*/\t()",
    "(?i)\\b\\(?[\"']*(?:assert(?:_options)?|c(?:hr|reate_function)|e(?:val|x(?:ec|p))|file(?:group)?|glob|i(?:mage(?:gif|(?:jpe|pn)g|wbmp|xbm)|s_a)|md5|o(?:pendir|rd)|p(?:assthru|open|rev)|(?:read|tmp)file|un(?:pac|lin)k|s(?:tat|ubstr|ystem))(?:/(?:\\*.*\\*/|/.*)|#.*|[\\s\\x0b\"])*[\"']*\\)?[\\s\\x0b]*\\(.*\\)",
    "s"
)
print(inspect(m))