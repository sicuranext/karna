PUT {{kong_api}}/services/{{service_id}}
Content-Type: application/json
```
{
  "name": "{{service_name}}",
  "host": "httpbin.org",
  "enabled": true,
  "protocol": "https",
  "port": 443,
  "path": "/anything"
}
```

PUT {{kong_api}}/services/{{service_id}}/routes/{{route_id}}
Content-Type: application/json
```
{
  "response_buffering": true,
  "hosts": [
    "{{service_host}}"
  ],
  "strip_path": false,
  "request_buffering": true,
  "preserve_host": true,
  "path_handling": "v1"
}
```

PUT {{kong_api}}/services/{{service_id}}/plugins/{{plugin_id}}
Content-Type: application/json
```
{
  "name": "karna",
  "config": {
    "enable_ooc_rules": false,
    "ignore_from_local_ips": false,
    "rules_request": [
        "{\"id\":\"13\",\"phase\":\"access\",\"conditions\":[{\"multi_match\":false,\"op\":\"rx\",\"transform\":[\"urlDecodeUni\"],\"value\":\"^foo\\\\s+bar$\",\"variables\":[\"request.arg.value\"]}],\"action\":{\"fixed_response\":{\"status_code\":403,\"headers\":{\"content-type\":\"text/plain\",\"cache-control\":\"max-age=0, private, no-store, no-cache, must-revalidate\"},\"body\":\"Forbidden\\r\\n\"}},\"message\":\"Thi is a test rule\",\"rule_control\":{},\"tags\":[\"test\",\"attack-xss\"]}"
    ],
    "private_debug": true,
    "redis_host": "redis",
    "redis_port": 6379,
    "redis_password": null,
    "engine_blocking_mode": true,
    "auditlog_enabled": true,
    "auditlog_path": "/usr/local/openresty/nginx/logs",
    "set_karna_headers": true
  },
  "enabled": true
}
```

#DELETE {{kong_api}}/services/{{service_id}}/routes/{{route_id}}

#DELETE {{kong_api}}/services/{{service_id}}
