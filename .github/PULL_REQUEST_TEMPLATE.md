## What this changes

A short description of the change and the motivation.

## Type

- [ ] Bug fix
- [ ] New feature (operator / variable / action / config option)
- [ ] Rule / CRS-fix change
- [ ] Docs
- [ ] Other:

## Testing

- [ ] `luac -p` passes on changed Lua files
- [ ] Unit tests pass (`lua ka-unittest/<name>.lua`)
- [ ] CRS PL1 regression run and **still 100%** (paste the pass count below)

```
# regression result
```

## Checklist

- [ ] I agree to the [CLA](../CLA.md)
- [ ] No internal/private paths or names in the diff (the anti-leak audit will check)
- [ ] `VERSION` in `handler.lua` and the rockspec bumped together (if releasing)
