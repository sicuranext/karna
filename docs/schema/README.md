# Karna rule JSON Schema

Machine-readable definition of the Karna rule format, JSON Schema draft 2020-12.

| File | Validates |
| --- | --- |
| `karna-rule.schema.json` | One rule object — a single `rules_request` entry. |
| `karna-rules.schema.json` | An array of rules — a global rules pack file, or the `json` payload published to the Redis hash `karna:global_rules`. |

Both are served from the docs site:

- <https://karna.sicuranext.com/docs/schema/karna-rule.schema.json>
- <https://karna.sicuranext.com/docs/schema/karna-rules.schema.json>

`karna-rules.schema.json` references the rule schema by its `$id`, so a
validator that works offline needs both files in the same directory.

## Validate

```bash
pip install jsonschema
python3 scripts/validate-rules.py global-rules.d/*.json
```

The bundled validator takes a single rule, a pack, or a JSON Lines file of
rules, resolves the schemas locally, and exits non-zero on the first bad file.
Any standard draft 2020-12 validator works too — see the
[JSON Schema section of the rule reference](https://karna.sicuranext.com/docs/rules.html#json-schema)
for editor setup and third-party validators.

## Keeping it honest

The schema is hand-maintained alongside `docs/rules.html` and the engine. When
an operator, transformation, action or rule control is added or renamed in
`kong/plugins/karna/modules/ka_engine.lua`, update the matching `$defs` block
here in the same commit. Every rule example in `docs/rules.html` and in the
skill reference validates against these files; that is the cheapest regression
test available for a drift of this kind.
