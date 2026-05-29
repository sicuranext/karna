# Karna — dev / integration-test image.
#
# Bakes the two non-Kong runtime requirements so the plugin can boot:
#   * libinjection.so at /usr/local/lib/libinjection.so (FFI-loaded by the plugin)
#   * OWASP CoreRuleSet at /opt/coreruleset/rules/      (default seclang.crs_path)
#
# The plugin source itself is NOT baked: docker-compose mounts it read-only
# from the repo and `luarocks make` is run at container start.

FROM kong:3.9.1

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
    # OWASP CRS: download tarball, strip top-level dir into /opt/coreruleset.
    # Download to a FILE (not `curl | tar`): a pipe masks curl's exit status
    # behind tar's, so under `set -e` (no pipefail) a transient network /
    # GitHub rate-limit failure would leave the rules dir EMPTY yet still
    # produce a "successful" image. Karna then loads ZERO CRS rules and
    # detection collapses — which surfaced as a CI regression false-failure
    # (~25% pass) that looked like a code regression but was a silent build
    # flake. Retry transient failures, then VERIFY the rules actually landed.
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
    # Install lua-zlib at image build time so `luarocks make` of the plugin
    # finds it (the plugin's rockspec lists it as a runtime dep).
    # Direct rockspec URL bypasses the luarocks.org manifest, which is too
    # large for LuaJIT to load (`main function has more than 65536 constants`).
    luarocks install https://luarocks.org/manifests/brimworks/lua-zlib-1.2-2.rockspec; \
    \
    # Audit log dir must be writable by Kong workers — the plugin writes here
    # asynchronously via ngx.timer.at on every request.
    mkdir -p /usr/local/openresty/nginx/logs; \
    chown -R kong:kong /usr/local/openresty/nginx/logs; \
    \
    # Trim the image: drop git + curl. KEEP build-essential/g++ and libre2-dev:
    # the karna RE2 spike (memory karna-re2-spike) compiles
    # src/libka_re2/ka_re2.cc -> /usr/local/lib/libka_re2.so at container start
    # (the plugin C source is mounted, not baked), so the toolchain + libre2
    # must persist at runtime. This is the dev/bench image — toolchain bloat is
    # acceptable here; a slim production image would prebuild the .so via COPY.
    rm -rf /tmp/libinjection; \
    apt-get purge -y --auto-remove git curl; \
    rm -rf /var/lib/apt/lists/*

# compose overrides USER to root so luarocks can install plugin to /usr/local
