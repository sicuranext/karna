# Deploying Karna

Two supported paths. Pick by context: use **Docker** for a fresh/self-contained
stack, use **existing Kong** when the operator already runs Kong.

## Path A — Docker (production, self-contained)

The production Dockerfile builds one image: Kong + OWASP CoreRuleSet + libinjection
+ the native RE2 / Aho-Corasick scanners + Karna. Kong runs DB-less; the
declarative config in `docker/kong.yml` puts Karna in front of the backend. Redis
is only used by `rate_limit` / `redis_incr_key` rules.

```sh
git clone https://github.com/sicuranext/karna.git
cd karna

# point the upstream at the app: edit docker/kong.yml
#   services[0].url: http://your-app:8080

docker compose -f docker/docker-compose.prod.yml up -d --build
# traffic: client -> :8000 (Karna / Kong) -> your app   (TLS proxy on :8443)
```

The image bakes in `KONG_PLUGINS=bundled,karna` and the PCRE backtracking cap
`KONG_NGINX_HTTP_LUA_REGEX_MATCH_LIMIT=100000`. Build args (overridable):
`LIBINJECTION_REF` (default `v3.10.0`), `CRS_VERSION` (default `4.26.0`).

## Path B — Install into an existing Kong

Kong 3.x on a Debian-like host. Build tools needed: `gcc`, `g++`, `zlib1g-dev`,
`libre2-dev`.

```sh
# 1. lua-zlib MUST come from the direct rockspec URL — the full luarocks.org
#    manifest is too large for LuaJIT to parse, so `luarocks install lua-zlib` fails.
luarocks install https://luarocks.org/manifests/brimworks/lua-zlib-1.2-2.rockspec

# 2. the plugin
cd /path/to/karna && luarocks make

# 3. libinjection.so (SQLi/XSS)
git clone --branch v3.10.0 https://github.com/client9/libinjection.git
cd libinjection/src && gcc -shared -fPIC -O2 -o /usr/local/lib/libinjection.so \
    libinjection_sqli.c libinjection_xss.c libinjection_html5.c && ldconfig

# 4. OWASP CoreRuleSet
mkdir -p /opt/coreruleset
curl -fsSL https://github.com/coreruleset/coreruleset/archive/refs/tags/v4.26.0.tar.gz \
    | tar -xz --strip-components=1 -C /opt/coreruleset

# 5. native scanners (optional — graceful fallback to pure Lua if absent)
g++ -shared -fPIC -O2 -std=c++17 -o /usr/local/lib/libka_re2.so src/libka_re2/ka_re2.cc -lre2
gcc -shared -fPIC -O2 -o /usr/local/lib/libka_ac.so src/libka_ac/ka_ac.c && ldconfig
```

Then wire Kong:

- `plugins = bundled,karna` in `kong.conf` (or `KONG_PLUGINS=bundled,karna`).
- `KONG_NGINX_HTTP_LUA_REGEX_MATCH_LIMIT=100000` (PCRE cap; non-negotiable).
- Expose the `KARNA_*` env vars to nginx workers: nginx wipes the environment, so
  set `KONG_NGINX_MAIN_INCLUDE=/path/to/main-env.conf` where the file contains:
  ```
  env KARNA_CRS_PATH;
  env KARNA_LIBINJECTION_SO;
  env KARNA_LIBKA_RE2_SO;
  env KARNA_PROFILE;
  ```
- Audit-log dir must be writable by the Kong worker user:
  `chown -R kong:kong /usr/local/openresty/nginx/logs`.
- `kong reload`.

### Env vars

| Var | Default | Purpose |
|-----|---------|---------|
| `KARNA_CRS_PATH` | `/opt/coreruleset/rules/` | CRS `rules/` directory |
| `KARNA_LIBINJECTION_SO` | `/usr/local/lib/libinjection.so` | libinjection path |
| `KARNA_LIBKA_RE2_SO` | `/usr/local/lib/libka_re2.so` | RE2 scanner (fallback to Lua if missing) |
| `KARNA_LIBKA_AC_SO` | `/usr/local/lib/libka_ac.so` | Aho-Corasick scanner (fallback to Lua if missing) |
| `KARNA_PROFILE` | unset | enables LuaJIT profiling (diagnostics) |

## Attaching Karna to a service

Declarative (`docker/kong.yml`, DB-less):

```yaml
_format_version: "3.0"
services:
  - name: my-app
    url: http://my-backend:8080
    routes:
      - name: my-app
        paths: ["/"]
    plugins:
      - name: karna
        config:
          engine_blocking_mode: false   # detection-only to start
          paranoia_level: 1
          auditlog_enabled: true
```

Admin API (running Kong):

```sh
curl -X POST http://localhost:8001/services/<service_id>/plugins \
  -H "Content-Type: application/json" \
  -d '{"name":"karna","config":{"engine_blocking_mode":false,"paranoia_level":1,"auditlog_enabled":true}}'
```

## Sanity checks after deploy

- `curl -s http://localhost:8001/plugins | grep karna` — plugin attached.
- `grep WARN $(kong prefix)/logs/error.log` after reload — any rule that failed to
  parse (e.g. an unsupported operator) is logged here, never silently.
- Send a known-bad request (e.g. `?x=<script>alert(1)</script>`) and confirm a
  match in the audit log (detection) or a 403 (blocking).
