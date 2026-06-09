#!/usr/bin/env bash
#
# install.sh — install Karna into an existing Kong / OpenResty host.
#
# Does everything the manual steps in the README do, in one command:
#   1. the plugin            (luarocks: lua-zlib via direct URL, then luarocks make)
#   2. libinjection.so       (SQLi / XSS, FFI-loaded)            -> $LIB_PREFIX
#   3. the OWASP CoreRuleSet                                     -> $CRS_PATH
#   4. the native scanners   (RE2 + Aho-Corasick, the fast path) -> $LIB_PREFIX
#
# Run it from anywhere; it locates the repo from its own path. Writing to
# /usr/local/lib and /opt usually needs root, so:
#
#   sudo ./scripts/install.sh
#
# Override defaults with env vars:
#   CRS_VERSION=4.26.0  CRS_PATH=/opt/coreruleset  LIBINJECTION_REF=v3.10.0
#   LIB_PREFIX=/usr/local/lib
#
# Skip pieces you already have:
#   --skip-deps          don't apt-install build dependencies
#   --skip-libinjection  don't build libinjection.so
#   --skip-crs           don't download the CoreRuleSet
#   --skip-native        don't build the RE2 / Aho-Corasick scanners
#
set -euo pipefail

CRS_VERSION="${CRS_VERSION:-4.26.0}"
CRS_PATH="${CRS_PATH:-/opt/coreruleset}"
LIBINJECTION_REF="${LIBINJECTION_REF:-v3.10.0}"
LIB_PREFIX="${LIB_PREFIX:-/usr/local/lib}"
LUA_ZLIB_ROCKSPEC="https://luarocks.org/manifests/brimworks/lua-zlib-1.4-0.rockspec"

SKIP_DEPS=0; SKIP_LIBINJECTION=0; SKIP_CRS=0; SKIP_NATIVE=0
for arg in "$@"; do
  case "$arg" in
    --skip-deps)         SKIP_DEPS=1 ;;
    --skip-libinjection) SKIP_LIBINJECTION=1 ;;
    --skip-crs)          SKIP_CRS=1 ;;
    --skip-native)       SKIP_NATIVE=1 ;;
    -h|--help)           sed -n '2,38p' "$0" | sed 's/^#\s\{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $arg (try --help)" >&2; exit 2 ;;
  esac
done

log()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ROCKSPEC="$(ls "$REPO_ROOT"/kong-plugin-karna-*.rockspec 2>/dev/null | head -1 || true)"
[ -n "$ROCKSPEC" ] || die "rockspec not found in $REPO_ROOT — run this from a Karna checkout"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

[ "$(id -u)" -eq 0 ] || warn "not running as root; writing to $LIB_PREFIX and $CRS_PATH may fail (re-run with sudo)"

# --- build dependencies (Debian / Ubuntu Kong images) ------------------------
if [ "$SKIP_DEPS" -eq 0 ] && have apt-get; then
  log "Installing build dependencies (apt-get)"
  apt-get update -qq
  apt-get install -y --no-install-recommends \
    ca-certificates curl git build-essential g++ zlib1g-dev libre2-dev \
    || warn "apt-get install failed; continuing (pass --skip-deps to silence)"
fi

# --- preflight ---------------------------------------------------------------
have luarocks || die "luarocks not found (it ships with Kong / OpenResty)"
have gcc      || die "gcc not found (apt-get install build-essential, or --skip-deps off)"

# --- 1. the plugin -----------------------------------------------------------
log "Installing lua-zlib (direct rockspec; the luarocks.org manifest is too big for LuaJIT)"
luarocks install "$LUA_ZLIB_ROCKSPEC"

# Stamp the build identity (version + git commit) into version.lua so the
# running plugin reports it on /.well-known/karna and in the audit log. git is
# available here (it's the repo); if it isn't, the committed placeholder
# ("unknown") is left in place and install still succeeds.
if have git && git -C "$REPO_ROOT" rev-parse HEAD >/dev/null 2>&1; then
  KA_COMMIT="$(git -C "$REPO_ROOT" rev-parse HEAD)"
  KA_SHORT="$(printf '%s' "$KA_COMMIT" | cut -c1-7)"
  KA_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  log "Stamping version.lua (commit ${KA_SHORT})"
  printf 'return {\n  version      = "1.1.1",\n  commit       = "%s",\n  commit_short = "%s",\n  built_at     = "%s",\n}\n' \
    "$KA_COMMIT" "$KA_SHORT" "$KA_DATE" > "$REPO_ROOT/kong/plugins/karna/version.lua"
fi

log "luarocks make (Karna plugin)"
( cd "$REPO_ROOT" && luarocks make "$ROCKSPEC" )

# --- 2. libinjection.so ------------------------------------------------------
if [ "$SKIP_LIBINJECTION" -eq 0 ]; then
  if [ -e "$LIB_PREFIX/libinjection.so" ]; then
    log "libinjection.so already at $LIB_PREFIX (skipping; --skip-libinjection to silence)"
  else
    have git || die "git needed to fetch libinjection (or pass --skip-libinjection)"
    log "Building libinjection $LIBINJECTION_REF -> $LIB_PREFIX/libinjection.so"
    git clone --depth 1 --branch "$LIBINJECTION_REF" \
      https://github.com/client9/libinjection.git "$TMP/li"
    gcc -shared -fPIC -O2 -o "$LIB_PREFIX/libinjection.so" \
      "$TMP/li/src/libinjection_sqli.c" \
      "$TMP/li/src/libinjection_xss.c" \
      "$TMP/li/src/libinjection_html5.c"
    have ldconfig && ldconfig || true
  fi
fi

# --- 3. OWASP CoreRuleSet ----------------------------------------------------
if [ "$SKIP_CRS" -eq 0 ]; then
  if [ -d "$CRS_PATH/rules" ] && \
     [ "$(find "$CRS_PATH/rules" -name '*.conf' 2>/dev/null | wc -l)" -ge 10 ]; then
    log "CRS already at $CRS_PATH/rules (skipping; --skip-crs to silence)"
  else
    have curl || die "curl needed to fetch the CoreRuleSet (or pass --skip-crs)"
    log "Downloading OWASP CRS v$CRS_VERSION -> $CRS_PATH"
    mkdir -p "$CRS_PATH"
    curl -fsSL --retry 5 --retry-delay 2 -o "$TMP/crs.tar.gz" \
      "https://github.com/coreruleset/coreruleset/archive/refs/tags/v$CRS_VERSION.tar.gz"
    tar -xz --strip-components=1 -C "$CRS_PATH" -f "$TMP/crs.tar.gz"
    n="$(find "$CRS_PATH/rules" -name '*.conf' 2>/dev/null | wc -l)"
    [ "$n" -ge 10 ] || die "CRS download looks empty ($n .conf files found)"
    log "CRS installed ($n rule files)"
  fi
fi

# --- 4. native scanners (optional, recommended) ------------------------------
# RE2::Set @rx gate + Aho-Corasick @pm. If a build fails the engine falls back
# to pure Lua (correct, just slower), so a failure here is a warning, not fatal.
if [ "$SKIP_NATIVE" -eq 0 ]; then
  if have g++; then
    log "Building native RE2 scanner -> $LIB_PREFIX/libka_re2.so"
    g++ -shared -fPIC -O2 -std=c++17 -o "$LIB_PREFIX/libka_re2.so" \
      "$REPO_ROOT/src/libka_re2/ka_re2.cc" -lre2 \
      || warn "libka_re2 build failed (need libre2-dev); engine_re2_scan falls back to Lua"
    log "Building native Aho-Corasick scanner -> $LIB_PREFIX/libka_ac.so"
    gcc -shared -fPIC -O2 -o "$LIB_PREFIX/libka_ac.so" \
      "$REPO_ROOT/src/libka_ac/ka_ac.c" \
      || warn "libka_ac build failed; engine_ac_pm falls back to Lua"
    have ldconfig && ldconfig || true
  else
    warn "g++ not found; skipping native scanners (engine flags fall back to Lua). apt-get install g++ libre2-dev to enable."
  fi
fi

# --- done --------------------------------------------------------------------
cat <<'EOF'

Karna installed. Next:

  1. Enable it in kong.conf (or via the KONG_PLUGINS env var):
       plugins = bundled,karna
       nginx_http_lua_regex_match_limit = 100000   # cap PCRE backtracking

  2. Reload Kong:
       kong reload

  3. Turn it on for a service (Admin API):
       curl -X POST http://localhost:8001/services/<service>/plugins \
         -d name=karna \
         -d config.engine_blocking_mode=false \
         -d config.paranoia_level=1 \
         -d config.auditlog_enabled=true

  Start in detection-only (engine_blocking_mode=false), watch the audit log,
  then set it to true to block.
EOF
