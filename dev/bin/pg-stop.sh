#!/usr/bin/env bash
# Stop the local dev postgres started by dev/bin/pg-start.sh (data preserved).
set -euo pipefail

PGDATA="${PGDATA:-$(pwd)/.nix-deps/pg}"

pg_ctl -D "${PGDATA}/data" stop -m fast
