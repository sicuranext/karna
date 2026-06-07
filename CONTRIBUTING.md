# Contributing to Karna

Thanks for your interest in improving Karna. This guide covers how to get a dev
environment running, how to test, and how changes are reviewed.

Questions and ideas are welcome on the [SicuraNext Discord](https://discord.gg/FaHMZfmqty)
(`#karna` channel) or in a GitHub issue.

## The CLA

Contributions require agreeing to the Contributor License Agreement — see
[CLA.md](CLA.md). The CLA assistant will prompt you on your first pull request.

## Development environment

Karna runs as a Kong Gateway plugin (Lua on OpenResty). The repo ships a
self-contained dev stack:

```sh
docker compose -f docker/docker-compose.dev.yml up -d --build
# Kong proxy on :28000, Admin API on :28001
```

The dev image builds the plugin, libinjection, the OWASP CoreRuleSet, and the
native RE2 / Aho-Corasick scanners. The repo `kong/` directory is mounted into
the container, so after editing Lua you apply the change with:

```sh
docker exec karna-kong sh -c \
  "cd /usr/local/kong/custom-plugins/karna/ && luarocks make && kong reload"
```

## Tests

- Lua syntax: `luac -p` runs on every file in CI.
- Unit tests: `lua ka-unittest/<name>.lua` (plain assertions, no framework).
- CRS regression (required for any engine or rule change):

  ```sh
  cd crs-regression-test
  ./fetch-tests.sh                    # PL1 in-scope test set
  PARANOIA=1 ./configure-kong.sh
  python3 start.py --testfile tests/
  ```

  PL1 is expected to stay at 100%. Run this and confirm no regression before
  opening a PR that touches the engine or the rules.

CI runs the syntax check, the unit tests, an anti-leak audit, and the PL1
regression on every push and pull request.

## Coding notes

- Match the style of the surrounding code: naming, comment density, idioms.
- Configuration and limits live in the plugin schema; detection rules detect
  attacks. Keep the two separate.
- Do not reference internal or private paths and names in source. The CI
  anti-leak audit fails the build if it finds them.
- Bump the `VERSION` in `handler.lua` and the rockspec version together on a
  release.

## Pull requests

- Keep each PR focused, and describe what changed and why.
- Include test output for engine or rule changes (the PL1 regression result).
- Be kind in review. See the [Code of Conduct](CODE_OF_CONDUCT.md).
