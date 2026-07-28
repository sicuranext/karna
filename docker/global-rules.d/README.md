# Example global rules pack (disk source)

This directory is an **example** of the disk source for Karna's global rules —
one pack evaluated on every service Karna is attached to. It is not mounted by
default: uncomment `KARNA_GLOBAL_RULES_PATH` and the matching volume in
`docker/docker-compose.dev.yml` to try it.

```sh
docker run ... \
    -e KARNA_GLOBAL_RULES_PATH=/etc/kong/karna/global-rules.d \
    -v ./global-rules.d:/etc/kong/karna/global-rules.d:ro \
    karna:latest
```

Rules of the road:

- Only `*.json` files are read, in **filename order** — that order is the
  evaluation order, so prefix them (`00-`, `10-`) when it matters. Pointing the
  variable at a single `.json` file works too.
- Each file is a bare JSON array of rules in the Karna rule format: the same
  objects `rules_request` takes, and the same array published to Redis as the
  `json` payload. No SecLang here.
- Blocking rules and exclusions can share a pack in any order. Exclusions (a
  `rule_control` with no `action`) are always evaluated first, so they reach the
  global detection rules, the local rules and the CRS.
- `@pmFromFile` is not supported on this channel; such a rule is dropped with a
  warning.
- The pack is read once per worker at startup. After an edit, `kong reload` (or
  recreate the container) — there is no filesystem watcher.

`10-example.json` holds one of each kind: a blocking rule keyed on a marker
header, and an exclusion that takes one argument out of a CRS rule's targets on
one path. See `docs/rules.html#global-rules` for the full reference.
