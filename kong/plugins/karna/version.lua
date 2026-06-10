-- Build identity for Karna. Committed with placeholders; the COMMIT and
-- BUILT_AT fields are stamped at build time:
--   * Docker:  docker/Dockerfile rewrites this file from build ARGs
--              (KARNA_COMMIT / KARNA_BUILD_DATE) before `luarocks make`.
--   * Source:  scripts/install.sh writes it from `git rev-parse HEAD`
--              before `luarocks make`.
-- A plain `luarocks make` with no stamping leaves the placeholders, so the
-- /.well-known/karna endpoint still answers (commit = "unknown").
--
-- `version` is the single source of truth for the engine version and must stay
-- in sync with the rockspec version and handler.lua's plugin.VERSION on release.
return {
  version      = "1.1.2",
  commit       = "unknown",
  commit_short = "unknown",
  built_at     = "unknown",
}
