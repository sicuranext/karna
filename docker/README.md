# Karna — local dev / integration-test stack

This stack spins up Kong + Postgres + Redis + an HTTP echo upstream so you
can exercise the plugin end-to-end without touching anything outside Docker.

## Layout

| Path | Purpose |
|---|---|
| `docker-compose.yml` (repo root) | Service definitions and port mappings. |
| `docker/kong/Dockerfile` | Custom Kong image: base `kong:3.9.0` + libinjection + OWASP CRS pre-installed. |
| `docker/kong/main-env.conf` | nginx `env` whitelist so worker processes can see `KARNA_CRS_PATH`. |

## Ports (shifted to avoid host clashes)

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

## Quickstart

```sh
docker compose up --build
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

## Pinned versions

The image bakes in:

- **libinjection** — `client9/libinjection` tag `v3.10.0`
- **OWASP CoreRuleSet** — `v4.26.0`

Both are overridable at build time:

```sh
docker compose build --build-arg CRS_VERSION=4.27.0 kong
```

## Live editing the plugin

The plugin source is bind-mounted read-only at
`/usr/local/kong/custom-plugins/karna/`. To pick up edits:

```sh
docker compose exec kong sh -c \
  'cd /usr/local/kong/custom-plugins/karna && luarocks make && kong reload'
```

Schema changes (anything in `schema.lua`) require a full restart, not just
a reload:

```sh
docker compose restart kong
```

## Running hurl integration tests

The existing tests in `ka-integration-tests/` default to
`kong_api=http://localhost:8001`. Override the variable to hit the docker
admin port:

```sh
hurl --variable kong_api=http://localhost:28001 \
     --variables-file ka-integration-tests/env \
     ka-integration-tests/000_rule_control.hurl
```

## Tearing down

```sh
docker compose down       # stop, keep volumes
docker compose down -v    # stop and wipe Postgres / Redis state
```
