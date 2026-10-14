# Karna Console

A web console for [Karna](../README.md), the WAF plugin for Kong Gateway. It reads
Karna's audit log and your Kong configuration, shows what Karna inspected and
stopped, and lets one administrator change how Karna protects each service.

- **Overview**: traffic and blocks over the last 24 hours, the most matched rules,
  the protection posture of every service.
- **Events**: one audit entry per request, with the matched rules, the request
  parts that matched and what Karna did. Filter, pivot by IP or rule, export NDJSON.
- **Services**: every Kong service that runs Karna, in blocking or detection mode,
  with its configuration.
- **Rules**: custom rules per service (native JSON or SecLang) and the overrides
  that change how CoreRuleSet rules behave.
- **Assistant**: a model you configure (OpenAI, Anthropic, OpenRouter, a local
  Ollama or LM Studio, or any OpenAI-compatible endpoint) that reads Karna's
  events, the Karna configuration, Kong and the Karna skill on its own, and
  proposes changes to Karna, Kong or the console. Every change waits for your
  Authorize click; see [Security model](#security-model).
- **Audit**: every change made from the console, with who made it and the content
  before and after.

## How it works

Two containers:

- `dashboard-web`: nginx serving the built React app, with a strict
  Content-Security-Policy. It proxies `/api` to the API, so the browser only ever
  talks to one origin.
- `dashboard-api`: a FastAPI service. It ingests Karna's audit log files (audit log
  v2, JSON Lines) into a local SQLite store, deletes each file once it is stored,
  and talks to the Kong Admin API to read services and to change Karna plugin
  configuration. It is not published to the host.

State lives on the `/data` volume of the API container: the admin account, the
event store, AI provider profiles and the change log.

## Requirements

- Kong Gateway with the Karna plugin, `auditlog_enabled: true` and audit log
  format `v2` (the default).
- The directory Karna writes audit logs to (`auditlog_path`) shared with the API
  container. The API consumes and deletes the files, so it needs write access to
  that directory: it runs as uid `1001`, the owner of Kong's log directory in the
  Karna image.
- Network access from the API container to the Kong Admin API.

## Run it

From the root of the Karna repository:

```sh
./quickstart.sh
```

It runs `docker compose up -d --build`, waits until everything is ready and prints
the console address and the setup token. After a `git pull`, run it again to
rebuild and restart what changed. Plain `docker compose up -d` works too, but it
reuses images that are already built: add `--build` after an update.
It starts Kong with Karna, the console, and a demo service:

- console: <http://127.0.0.1:9080>
- proxy: <http://127.0.0.1:8000>, a demo service behind Karna in blocking mode.
  Try `curl "http://127.0.0.1:8000/?q=<script>alert(1)</script>"` and watch
  the block show up in the console.

The demo service is created on the first start only; manage it or delete it from
the console. Both ports are published on the loopback address only. Read
[Exposing the console](#exposing-the-console) before opening the console to the
network; to reach the proxy from other machines set `KARNA_PROXY_BIND=0.0.0.0`.
`KARNA_PROXY_PORT` and `KARNA_CONSOLE_PORT` change the two ports.

Each container only reaches what it needs. The Kong Admin API is not published
and listens only on the network Kong shares with the console API; the demo
service reaches Kong's proxy and nothing else; Postgres and Redis are reachable
from Kong only. On the first run `quickstart.sh` writes a random Postgres
password to `.env` (`KARNA_PG_PASSWORD`); an existing database keeps its own.

To stop it, `docker compose down`. Add `-v` to also delete the data (the Kong
database, the admin account and the stored events).

Working on Karna itself? The console also runs on top of the development stack:

```sh
docker compose -f docker/docker-compose.dev.yml -f dashboard/docker-compose.yml up -d --build
```

### First run: the setup token

On first start no administrator exists. Whoever could reach the console in that
moment could otherwise create the admin account and take it over, so creating it
requires a one-time **setup token** that only someone with access to the server
can read. The API prints it in its log:

```sh
docker compose logs dashboard-api
```

Open the console, paste the token, and choose the admin email and password (at
least 10 characters). The token stops working as soon as the admin exists, and the
log stops printing it. To choose the token yourself, for example from a secret
manager, set `KARNA_DASH_SETUP_TOKEN` on the API container.

## Exposing the console

The console serves plain HTTP. On the machine itself that is fine. From anywhere
else, the password at sign-in and the session token on every request would cross
the network unencrypted, readable by anyone on the path, and that session can
change your WAF configuration. The sign-in page shows a warning when it is opened
this way.

Pick one of these:

- **Local only** (the default): use it from the machine that runs it.
- **SSH tunnel**: nothing exposed, nothing to configure on the server.

  ```sh
  ssh -L 28080:127.0.0.1:28080 you@server    # then open http://127.0.0.1:28080
  ```

- **HTTPS reverse proxy** in front of `127.0.0.1:28080`, sending
  `X-Forwarded-Proto: https` so the console also turns on HSTS. With Caddy, for
  example:

  ```
  console.example.com {
      reverse_proxy 127.0.0.1:28080 {
          header_up X-Forwarded-Proto https
      }
  }
  ```

Never publish port 28080 on all interfaces (`0.0.0.0`): Docker's port publishing
bypasses host firewalls such as ufw.

## Configuration

API container (`dashboard-api`):

| Variable | Default | Purpose |
| --- | --- | --- |
| `KONG_ADMIN_URL` | `http://kong:8001` | Kong Admin API used until a connection is saved in Settings. |
| `KONG_ADMIN_TOKEN` | unset | Kong Admin API token (Kong Enterprise RBAC). |
| `KONG_ADMIN_TOKEN_ORIGIN` | `KONG_ADMIN_URL` | The only origin (`scheme://host:port`) the token is ever sent to. |
| `KARNA_AUDITLOG_DIR` | `/var/log/karna` | Where the API reads Karna's audit log files. |
| `KARNA_DASH_DATA` | `/data` | State directory (account, event store, profiles, change log). |
| `KARNA_DASH_SETUP_TOKEN` | generated | First-run setup token; see above. |
| `KARNA_DASH_SECRET` | generated | Session signing secret, at least 32 characters. |
| `KARNA_DASH_CREDENTIAL_KEY` | generated | Fernet key that encrypts AI provider keys. Set it from a secret manager to keep it off the `/data` volume. |
| `KARNA_DASH_TOKEN_TTL` | `43200` | Session lifetime in seconds. |
| `KARNA_DASH_TTL_DAYS` | `30` | Default event retention, editable in Settings. |
| `KARNA_DASH_MAX_EVENTS` | `1000000` | Ceiling of stored events; the oldest are dropped first. |
| `KARNA_INGEST_INTERVAL` | `5` | Seconds between audit log scans. |
| `KARNA_KONG_INVENTORY_TTL` | `300` | Seconds the Kong services/routes/plugins inventory is cached. |
| `KARNA_MAX_AUDIT_FILES` | `3000` | Recent events used to compute the statistics. |
| `KARNA_MAX_EVENTS` | `300` | Recent events listed on the Events page. |
| `KARNA_CRS_VERSION` | `4.x` | CoreRuleSet version shown in the console. |

## Security model

- **One administrator.** Created on first run with the setup token; registration
  is then closed. Settings has password change and "Sign out everywhere"; both
  revoke every session. Sessions are bearer tokens kept in the browser tab's
  session storage, so there are no cookies and no CSRF surface.
- **Sign-in lockout.** After ten failed attempts in 15 minutes, from any
  address, sign-in locks for everyone and each further failure doubles the
  lockout (30 seconds up to 15 minutes). The console is meant to be reachable
  from trusted addresses only (see [Exposing the console](#exposing-the-console)),
  so the count is global instead of per address. Restarting the API container
  clears a lockout. nginx also rate-limits the credential endpoints.
- **What the console can change.** From its own pages: the configuration of
  Karna plugins (engine settings, custom rules, overrides) and its own settings.
  Through the assistant, after your authorization: anything the Kong Admin API
  allows, plus Karna and the console's retention. Never the console account or
  the AI provider keys. Every change is recorded in the change log. Edits address
  a rule or an entity by its content, so something changed elsewhere in the
  meantime is never overwritten by mistake.
- **The assistant never changes anything by itself.** Every tool call it makes
  goes through a deterministic classifier, plain code with no model involved:
  reads run (events, configuration, `GET` on the Kong Admin API, the Karna
  skill); anything else is a write, which never runs during the model's turn;
  unknown tools, paths outside the Admin API and malformed calls are refused.
  A write becomes a card in the chat, with the server's own description of the
  change (the entity now, the entity after, and what weakens the WAF or deletes
  something), and runs only when you click **Authorize**: once, for exactly
  that operation, within ten minutes, and only if the entity has not changed
  since. Risky changes also need their confirmation text typed back. Audit
  events contain data chosen by whoever sent the request, so a prompt injection
  in one can at most produce a card you see and reject.
- **Secrets stay out of the model.** Before anything reaches the provider, the
  console replaces with `[REDACTED]` every value whose name says it is a
  credential: fields such as `password`, `key`, `aws_secret` or `provision_key`,
  `Name: value` header strings such as `X-Api-Key: ...` in plugin configs, query
  and body parameters such as `?apikey=` in audit events, and matched values
  taken from a session cookie or a password field. A secret kept under a name
  that does not look like one is not recognised, so name such fields
  accordingly. `/config` (the whole declarative configuration on a DB-less
  Kong) is never read, and a write that would put a redacted placeholder back
  is refused.
- **Credentials.** AI provider keys are encrypted at rest and never sent back to
  the browser, and a saved key is only used for the provider and endpoint it was
  saved for. The Kong Admin token is only sent to its configured origin.
- **Outbound requests.** The API reaches Kong and AI providers on private and
  loopback addresses as needed, but never link-local or cloud metadata addresses
  (such as `169.254.169.254`), whatever a hostname resolves to.
- **Containers.** Both console containers run as non-root users with all
  capabilities dropped and a read-only root filesystem. In the quickstart, Kong
  and the demo service also drop every capability; Postgres and Redis keep only
  the few their entrypoints need to own the data directory and switch to their
  own user. Every image is pinned by digest, and Python packages are installed
  only if they match the hashes in `api/requirements.txt`.

Audit records contain the requests Karna inspected, including data an attacker
sent. The console displays them as text and never renders them as HTML.

## Development

```sh
cd dashboard/web
npm ci
npm run dev        # http://localhost:5173 with built-in sample data, no backend needed
npm run lint
npm run build
```

Backend tests:

```sh
cd dashboard/api
KARNA_DASH_DATA=$(mktemp -d) python3 -m unittest discover -p "test_*.py"
```

Python dependencies are declared in `api/requirements.in`; `api/requirements.txt`
is generated from it with hashes:

```sh
docker run --rm -v "$PWD/api:/w" -w /w python:3.12-slim \
  sh -c 'pip install -q pip-tools && pip-compile --generate-hashes --allow-unsafe --strip-extras -o requirements.txt requirements.in'
```

## License

Karna Console is part of Karna and is provided under the
[Elastic License 2.0](../LICENSE).

Karna, the Karna logo, SicuraNext and the SicuraNext logo are trademarks of
SicuraNext s.r.l. The license does not grant rights to use them.

Manrope and IBM Plex Mono are bundled under the SIL Open Font License 1.1; the
license texts are in `web/src/assets/fonts/`.
