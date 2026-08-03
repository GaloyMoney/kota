#!/usr/bin/env bash
# Start a local dev postgres (data in .nix-deps/pg), create the database,
# and run migrations. Idempotent. Stop with dev/bin/pg-stop.sh.
set -euo pipefail

PGDATA="${PGDATA:-$(pwd)/.nix-deps/pg}"
PGPORT="${PGPORT:-5441}"
PGDATABASE="${PGDATABASE:-kota}"
export DATABASE_URL="${DATABASE_URL:-postgres://user:password@127.0.0.1:${PGPORT}/${PGDATABASE}}"

if [ ! -d "${PGDATA}/data" ]; then
  mkdir -p "${PGDATA}"
  initdb -D "${PGDATA}/data" -U user --auth=trust >/dev/null
  echo "initialized postgres data dir at ${PGDATA}/data"
fi

pg_ctl -D "${PGDATA}/data" \
  -o "-p ${PGPORT} -k ${PGDATA} -c listen_addresses=127.0.0.1" \
  -l "${PGDATA}/log" -w start >/dev/null

createdb -h 127.0.0.1 -p "${PGPORT}" -U user "${PGDATABASE}" 2>/dev/null || true

sqlx migrate run

echo "postgres ready: ${DATABASE_URL}"
