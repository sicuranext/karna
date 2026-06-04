# Karna — Docker

All Docker assets live in this folder. One multi-stage `Dockerfile` builds both
the dev and prod images; two compose files drive the two stacks.

| Path | Purpose |
|---|---|
| `docker/Dockerfile` | Multi-stage image. `base` = Kong 3.9.1 + libinjection + OWASP CRS + lua-zlib + native RE2/Aho-Corasick scanners (no plugin). `prod` = `base` + the plugin baked in. |
| `docker/docker-compose.prod.yml` | Production stack: DB-less Kong + Redis, Karna in front of your app. |
| `docker/docker-compose.dev.yml` | Local dev / integration stack: Postgres + Redis + Kong + echo upstream, with the plugin bind-mounted and `luarocks make` run at start. |
| `docker/kong.yml` | DB-less declarative config template used by the prod stack. |
| `docker/main-env.conf` | nginx `env` whitelist so worker processes can see `KARNA_*` env vars. |

All commands below are run **from the repo root** (the build context is the
root; the compose files reference it with `context: ..`).

## Production (self-contained image)

```sh
# build the prod image (the plugin is baked in)
docker build -f docker/Dockerfile -t karna .

# edit docker/kong.yml -> point the service url at your app, then:
docker compose -f docker/docker-compose.prod.yml up -d
```

Traffic flows `client -> :8000 (Karna / Kong) -> your app`. Start with
`engine_blocking_mode: false` (detection-only), then flip it to `true` to block.
Redis is only used by `rate_limit` rules.

## Local dev / integration stack

Builds the `base` stage and bind-mounts the plugin source, so edits are picked
up with a `luarocks make` + reload instead of an image rebuild.

```sh
docker compose -f docker/docker-compose.dev.yml up --build
# wait for "Kong started" in the logs

# admin API alive?
curl http://localhost:28001/ | jq .version

# create a service routed to the in-stack echo, with karna on top
curl -sX PUT http://localhost:28001/services/demo \
  -d host=echo -d port=8080 -d protocol=http
curl -sX PUT http://localhost:28001/services/demo/routes/demo-route \
  -d 'paths[]=/demo' -d strip_path=true
curl -sX PUT http://localhost:28001/services/demo/plugins \
  -d name=karna \
  -d config.engine_blocking_mode=true

# clean request: should reach the echo (HTTP 200)
curl -i 'http://localhost:28000/demo/'

# obvious SQLi: should be blocked (HTTP 403) when CRS is enabled
curl -i 'http://localhost:28000/demo/?id=1%27%20OR%201=1--'
```

### Ports (shifted to avoid host clashes)

| Service | Host port | Container port |
|---|---|---|
| Kong proxy | 28000 | 8000 |
| Kong proxy SSL | 28443 | 8443 |
| Kong admin API | 28001 | 8001 |
| Kong admin SSL | 28444 | 8444 |
| Kong Manager | 28002 | 8002 |
| Postgres | 25432 | 5432 |
| Redis | 26379 | 6379 |
| Echo upstream | _internal only_ | 8080 |

### Live editing the plugin

The plugin source is bind-mounted read-only. To pick up edits:

```sh
docker compose -f docker/docker-compose.dev.yml exec kong sh -c \
  'cd /usr/local/kong/custom-plugins/karna && luarocks make && kong reload'
```

Schema changes (anything in `schema.lua`) require a full restart, not just a
reload:

```sh
docker compose -f docker/docker-compose.dev.yml restart kong
```

### Running hurl integration tests

The tests in `ka-integration-tests/` default to `kong_api=http://localhost:8001`.
Override the variable to hit the docker admin port:

```sh
hurl --variable kong_api=http://localhost:28001 \
     --variables-file ka-integration-tests/env \
     ka-integration-tests/000_rule_control.hurl
```

### Tearing down

```sh
docker compose -f docker/docker-compose.dev.yml down       # stop, keep volumes
docker compose -f docker/docker-compose.dev.yml down -v    # also wipe Postgres / Redis state
```

## Pinned versions

The image bakes in:

- **libinjection** — `client9/libinjection` tag `v3.10.0`
- **OWASP CoreRuleSet** — `v4.26.0`

Both are overridable at build time:

```sh
docker build -f docker/Dockerfile --build-arg CRS_VERSION=4.27.0 -t karna .
```
