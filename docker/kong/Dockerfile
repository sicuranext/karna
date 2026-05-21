# Karna — dev / integration-test image.
#
# Bakes the two non-Kong runtime requirements so the plugin can boot:
#   * libinjection.so at /usr/local/lib/libinjection.so (FFI-loaded by the plugin)
#   * OWASP CoreRuleSet at /opt/coreruleset/rules/      (default seclang.crs_path)
#
# The plugin source itself is NOT baked: docker-compose mounts it read-only
# from the repo and `luarocks make` is run at container start.

FROM kong:3.9.0

USER root

ARG LIBINJECTION_REF=v3.10.0
ARG CRS_VERSION=4.26.0

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates curl git build-essential zlib1g-dev; \
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
    mkdir -p /opt/coreruleset; \
    curl -fsSL "https://github.com/coreruleset/coreruleset/archive/refs/tags/v${CRS_VERSION}.tar.gz" \
        | tar -xz --strip-components=1 -C /opt/coreruleset; \
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
    # Trim the image: drop build deps, keep only ca-certificates + zlib runtime.
    rm -rf /tmp/libinjection; \
    apt-get purge -y --auto-remove git build-essential curl; \
    rm -rf /var/lib/apt/lists/*

# compose overrides USER to root so luarocks can install plugin to /usr/local
