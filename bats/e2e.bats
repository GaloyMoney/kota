#!/usr/bin/env bats

# End-to-end smoke test for the coordination backend.
#
# Boots a dedicated postgres (own port, own data dir — no interference
# with the dev instance or other clones), runs migrations, then drives
# the full flow through the test suites against it:
#
#   unit: entity state machines, idempotency, PSBT validation
#   e2e:  propose -> platform jobs build the unsigned PSBT -> signers
#         sign with real keys -> additive-only validation -> finalization
#         job recomputes the final tx (real job executor, real DB)
#
# Run from the repo root inside the dev shell: `bats bats/e2e.bats`.

BATS_PGPORT="${BATS_PGPORT:-5443}"
BATS_PGDATA="$(pwd)/.nix-deps/pg-bats"
BATS_PGDATABASE="multisig_bats"
export BATS_DATABASE_URL="postgres://user:password@127.0.0.1:${BATS_PGPORT}/${BATS_PGDATABASE}"

setup_file() {
  PGDATA="$BATS_PGDATA" \
  PGPORT="$BATS_PGPORT" \
  PGDATABASE="$BATS_PGDATABASE" \
  DATABASE_URL="$BATS_DATABASE_URL" \
    ./dev/bin/pg-start.sh
}

teardown_file() {
  PGDATA="$BATS_PGDATA" ./dev/bin/pg-stop.sh
  # clean up per-test databases created by the app-flow suite
  PGPORT="$BATS_PGPORT" psql "postgres://user:password@127.0.0.1:${BATS_PGPORT}/postgres" -tAc \
    "SELECT datname FROM pg_database WHERE datname LIKE 'kota_test_%'" \
    | while read -r db; do
        PGPORT="$BATS_PGPORT" psql "postgres://user:password@127.0.0.1:${BATS_PGPORT}/postgres" \
          -c "DROP DATABASE \"$db\"" >/dev/null
      done
}

@test "rustfmt is clean" {
  run cargo fmt --check
  [ "$status" -eq 0 ]
}

@test "clippy is clean" {
  run env SQLX_OFFLINE=true cargo clippy --workspace --all-targets -- -D warnings
  [ "$status" -eq 0 ]
}

@test "unit tests pass (no database)" {
  run env SQLX_OFFLINE=true cargo test --workspace --lib
  [ "$status" -eq 0 ]
}

@test "integration suites pass against real postgres and the job executor" {
  run env DATABASE_URL="$BATS_DATABASE_URL" cargo test --workspace
  [ "$status" -eq 0 ]
}
