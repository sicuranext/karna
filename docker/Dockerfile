# Karna — Docker image (multi-stage).
#
# One source of truth for the heavy build steps, two stages:
#   base  — Kong + libinjection + OWASP CRS + lua-zlib + the native RE2 /
#           Aho-Corasick scanners. The plugin is NOT baked: the dev stack
#           (docker-compose.dev.yml) bind-mounts the source and runs
#           `luarocks make` at container start for live iteration.
#   prod  — base + the plugin baked in. Self-contained, no mounts. Default target.
#
# The build context is the REPO ROOT (COPY paths are repo-relative):
#   docker build -f docker/Dockerfile -t karna .
#
# Build args (override with --build-arg):
#   LIBINJECTION_REF  libinjection git tag (SQLi/XSS, FFI-loaded)
#   CRS_VERSION       OWASP CoreRuleSet release

# ---------------------------------------------------------------- base --------
FROM kong:3.9.1 AS base

USER root

ARG LIBINJECTION_REF=v3.10.0
ARG CRS_VERSION=4.26.0

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates curl git build-essential g++ zlib1g-dev \
        libre2-dev; \
    \
    # libinjection: build .so from official source.
    git clone --depth 1 --branch "${LIBINJECTION_REF}" \
        https://github.com/client9/libinjection.git /tmp/libinjection; \
    gcc -shared -fPIC -O2 \
        -o /usr/local/lib/libinjection.so \
        /tmp/libinjection/src/libinjection_sqli.c \
        /tmp/libinjection/src/libinjection_xss.c \
        /tmp/libinjection/src/libinjection_html5.c; \
    ldconfig; \
    \
    # OWASP CRS: download to a FILE (not `curl | tar`, which masks curl's exit
    # status behind tar's and can ship an empty rules dir on a transient
    # failure), strip the top-level dir, then VERIFY the rules landed.
    mkdir -p /opt/coreruleset; \
    curl -fsSL --retry 5 --retry-delay 2 -o /tmp/crs.tar.gz \
        "https://github.com/coreruleset/coreruleset/archive/refs/tags/v${CRS_VERSION}.tar.gz"; \
    tar -xz --strip-components=1 -C /opt/coreruleset -f /tmp/crs.tar.gz; \
    rm -f /tmp/crs.tar.gz; \
    crs_conf_count="$(find /opt/coreruleset/rules -name '*.conf' 2>/dev/null | wc -l)"; \
    test "${crs_conf_count}" -ge 10 \
        || { echo "FATAL: CRS rules missing after download (found ${crs_conf_count} .conf)"; exit 1; }; \
    echo "CRS ${CRS_VERSION}: ${crs_conf_count} rule files installed"; \
    \
    # lua-zlib (gzip bodies). Direct rockspec URL: the luarocks.org manifest is
    # too large for LuaJIT to load (main function > 65536 constants).
    luarocks install https://luarocks.org/manifests/brimworks/lua-zlib-1.2-2.rockspec; \
    \
    rm -rf /tmp/libinjection

# Native scanners that back the default-on fast path (RE2::Set @rx gate,
# Aho-Corasick @pm). Baked so the engine flags work out of the box; the dev
# stack recompiles them from the bind-mounted source at startup.
COPY src/libka_re2 /tmp/libka_re2
COPY src/libka_ac  /tmp/libka_ac
RUN set -eux; \
    g++ -shared -fPIC -O2 -std=c++17 -o /usr/local/lib/libka_re2.so /tmp/libka_re2/ka_re2.cc -lre2; \
    gcc -shared -fPIC -O2 -o /usr/local/lib/libka_ac.so /tmp/libka_ac/ka_ac.c; \
    ldconfig; \
    rm -rf /tmp/libka_re2 /tmp/libka_ac; \
    # Audit-log dir must be writable by the Kong worker user.
    mkdir -p /usr/local/openresty/nginx/logs; \
    chown -R kong:kong /usr/local/openresty/nginx/logs; \
    # Drop the transfer tools. build-essential / g++ / libre2-dev stay: the dev
    # stack recompiles the native libs at runtime, and libre2 is libka_re2.so's
    # runtime dependency.
    apt-get purge -y --auto-remove git curl; \
    rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------- prod --------
# base + the plugin baked in. Self-contained: no bind mounts, no luarocks make
# at container start. This is the default build target.
FROM base AS prod

COPY kong/ /tmp/karna/kong/
COPY kong-plugin-karna-1.0.0-0.rockspec /tmp/karna/
RUN set -eux; \
    cd /tmp/karna; \
    luarocks make; \
    cd /; \
    rm -rf /tmp/karna

# Karna is enabled and the PCRE backtracking cap is set, so the image is safe
# and ready by default. Point KONG_DATABASE / KONG_DECLARATIVE_CONFIG at your
# declarative config at run time.
ENV KONG_PLUGINS=bundled,karna \
    KONG_NGINX_HTTP_LUA_REGEX_MATCH_LIMIT=100000

USER kong
