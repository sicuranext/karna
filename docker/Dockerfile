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
#   WORDPRESS_CRS_PLUGIN_VERSION  official WordPress exclusion plugin release

# ---------------------------------------------------------------- base --------
FROM kong:3.9.2@sha256:bcc27182e9bd2e696aee55ec6cb83f64ec0bfba2143914489dadb44f4f839b19 AS base

USER root

ARG LIBINJECTION_REF=v3.10.0
ARG LIBINJECTION_SHA=bf234eb2f385b969c4f803b35fda53cffdd93922
ARG CRS_VERSION=4.26.0
ARG CRS_SHA256=d923e991e671d2665cd73758b8dc3df6c3b0a9df96d798e98f088d5a81a76dc0
ARG WORDPRESS_CRS_PLUGIN_VERSION=1.2.0
ARG WORDPRESS_CRS_PLUGIN_SHA256=8a1fc80dcf6030b13f856dcaa72dcac898b4375fe5a41689ed96d6e895929439

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates curl git build-essential g++ zlib1g-dev \
        libre2-dev; \
    \
    # libinjection: build .so from official source.
    git clone --depth 1 --branch "${LIBINJECTION_REF}" \
        https://github.com/client9/libinjection.git /tmp/libinjection; \
    # Tags are mutable pointers: verify the cloned commit is the expected one.
    test "$(git -C /tmp/libinjection rev-parse HEAD)" = "${LIBINJECTION_SHA}" \
        || { echo "FATAL: libinjection ${LIBINJECTION_REF} resolved to an unexpected commit (tag moved?)"; exit 1; }; \
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
    echo "${CRS_SHA256}  /tmp/crs.tar.gz" | sha256sum -c -; \
    tar -xz --strip-components=1 -C /opt/coreruleset -f /tmp/crs.tar.gz; \
    rm -f /tmp/crs.tar.gz; \
    crs_conf_count="$(find /opt/coreruleset/rules -name '*.conf' 2>/dev/null | wc -l)"; \
    test "${crs_conf_count}" -ge 10 \
        || { echo "FATAL: CRS rules missing after download (found ${crs_conf_count} .conf)"; exit 1; }; \
    echo "CRS ${CRS_VERSION}: ${crs_conf_count} rule files installed"; \
    \
    # Official CRS WordPress exclusions. Keep the archive pinned and verified
    # like the core ruleset; Karna enables it per service via
    # config.crs_plugins_enabled.
    mkdir -p /opt/coreruleset-plugins/wordpress-rule-exclusions-plugin; \
    curl -fsSL --retry 5 --retry-delay 2 -o /tmp/wordpress-crs-plugin.tar.gz \
        "https://github.com/coreruleset/wordpress-rule-exclusions-plugin/archive/refs/tags/v${WORDPRESS_CRS_PLUGIN_VERSION}.tar.gz"; \
    echo "${WORDPRESS_CRS_PLUGIN_SHA256}  /tmp/wordpress-crs-plugin.tar.gz" | sha256sum -c -; \
    tar -xz --strip-components=1 \
        -C /opt/coreruleset-plugins/wordpress-rule-exclusions-plugin \
        -f /tmp/wordpress-crs-plugin.tar.gz; \
    rm -f /tmp/wordpress-crs-plugin.tar.gz; \
    wordpress_conf_count="$(find /opt/coreruleset-plugins/wordpress-rule-exclusions-plugin/plugins -name '*.conf' 2>/dev/null | wc -l)"; \
    test "${wordpress_conf_count}" -ge 2 \
        || { echo "FATAL: WordPress CRS plugin rules missing (found ${wordpress_conf_count} .conf)"; exit 1; }; \
    echo "WordPress CRS plugin ${WORDPRESS_CRS_PLUGIN_VERSION}: ${wordpress_conf_count} files installed"; \
    \
    # lua-zlib (gzip bodies). Direct rockspec URL: the luarocks.org manifest is
    # too large for LuaJIT to load (main function > 65536 constants).
    luarocks install https://luarocks.org/manifests/brimworks/lua-zlib-1.4-0.rockspec; \
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

# Build identity, stamped into version.lua before install. `.git` is excluded
# from the build context (see .dockerignore) and git is purged in `base`, so the
# commit must be passed in: `--build-arg KARNA_COMMIT=$(git rev-parse HEAD)`
# (scripts/build.sh does this). Defaults keep an unstamped build working.
ARG KARNA_COMMIT=unknown
ARG KARNA_BUILD_DATE=unknown

COPY kong/ /tmp/karna/kong/
COPY kong-plugin-karna-1.4.3-0.rockspec /tmp/karna/
RUN set -eux; \
    cd /tmp/karna; \
    short="$(printf '%s' "$KARNA_COMMIT" | cut -c1-7)"; \
    printf 'return {\n  version      = "1.4.3",\n  commit       = "%s",\n  commit_short = "%s",\n  built_at     = "%s",\n}\n' \
        "$KARNA_COMMIT" "$short" "$KARNA_BUILD_DATE" > kong/plugins/karna/version.lua; \
    luarocks make; \
    cd /; \
    rm -rf /tmp/karna

# Env whitelist for nginx worker processes: nginx wipes the environment, so
# every KARNA_* var read via os.getenv() at init_worker (CRS path overrides,
# KARNA_REDIS_URL / KARNA_GLOBAL_RULES_* for the global rules pack) must be
# declared with `env NAME;` in the main context. Baking the include makes the
# image work with plain `docker run -e KARNA_REDIS_URL=...`; declaring an
# unset var is harmless. If you override KONG_NGINX_MAIN_INCLUDE, keep these
# lines in your snippet.
COPY docker/main-env.conf /etc/kong/nginx/main-env.conf

# Karna is enabled and the PCRE backtracking cap is set, so the image is safe
# and ready by default. Point KONG_DATABASE / KONG_DECLARATIVE_CONFIG at your
# declarative config at run time.
ENV KONG_PLUGINS=bundled,karna \
    KONG_NGINX_HTTP_LUA_REGEX_MATCH_LIMIT=100000 \
    KONG_NGINX_MAIN_INCLUDE=/etc/kong/nginx/main-env.conf

USER kong
