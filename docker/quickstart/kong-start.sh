#!/bin/sh
# Karna quickstart (compose.yaml): prepare the Kong database, import the demo
# service on the very first start only, then run Kong in the foreground.
set -e

# `kong migrations list` exits 3 when the database was never bootstrapped.
rc=0
kong migrations list >/dev/null 2>&1 || rc=$?

if [ "$rc" -eq 3 ]; then
  kong migrations bootstrap
  kong config db_import /quickstart/kong.yml
  echo "karna quickstart: demo service imported"
else
  kong migrations up
  kong migrations finish
fi

# The Admin API listens on Kong's address on the control network only (where
# the console API is) and on loopback: never on the networks it shares with
# the demo upstream, Postgres or Redis. Fail closed when the address is unknown.
admin_ip="$(getent hosts kong-admin | awk '{print $1; exit}')"
if [ -z "$admin_ip" ]; then
  echo "karna quickstart: cannot resolve kong-admin on the control network" >&2
  exit 1
fi
export KONG_ADMIN_LISTEN="${admin_ip}:8001, 127.0.0.1:8001"

exec /docker-entrypoint.sh kong docker-start
