REPO_ROOT=$(git rev-parse --show-toplevel)

KOTA_SERVER_URL="${KOTA_SERVER_URL:-http://localhost:5256}"
GQL_ENDPOINT="${KOTA_SERVER_URL}/graphql"
KOTA_BIN="${KOTA_BIN:-${REPO_ROOT}/target/debug/kota-cli}"

# Not named BATS_* — bats itself owns that namespace (BATS_ROOT in
# particular is bats' own install path).
KOTA_RUN_DIR="${REPO_ROOT}/tmp/bats/kota"
mkdir -p "$KOTA_RUN_DIR"
LOG_FILE="$KOTA_RUN_DIR/server.log"
SERVER_PID_FILE="$KOTA_RUN_DIR/server-pid"
CACHE_DIR="$KOTA_RUN_DIR/cache"
mkdir -p "$CACHE_DIR"

cache_value() {
  echo "$2" > "$CACHE_DIR/$1"
}

read_value() {
  cat "$CACHE_DIR/$1" 2>/dev/null
}

# RFC4122-shaped uuid from /dev/urandom — no uuidgen dependency.
random_uuid() {
  local hex
  hex=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
  echo "${hex:0:8}-${hex:8:4}-${hex:12:4}-${hex:16:4}-${hex:20:12}"
}

random_seed() {
  od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
}

# Deterministic test keystore (descriptor public key) for a seed, via
# the CLI's dev helper — fresh seeds per run, so wallets never collide
# with previous runs' descriptor fingerprints.
gen_keystore() {
  "$KOTA_BIN" dev gen-keystore --seed "$1"
}

# --- server lifecycle (lana's reuse-healthy-server pattern) ---

ensure_pg() {
  if ! pg_isready -h 127.0.0.1 -p "${PGPORT:-5441}" >/dev/null 2>&1; then
    "${REPO_ROOT}/dev/bin/pg-start.sh"
  fi
}

start_server() {
  echo "--- Starting server ---"

  if curl -sf "${KOTA_SERVER_URL}/health" >/dev/null 2>&1; then
    echo "--- Reusing healthy running server ---"
    return 0
  fi

  if [[ -f "$SERVER_PID_FILE" ]]; then
    local existing_pid
    existing_pid=$(cat "$SERVER_PID_FILE")
    if kill -0 "$existing_pid" 2>/dev/null; then
      echo "--- Found unhealthy kota server process $existing_pid, stopping it ---"
      kill "$existing_pid" 2>/dev/null || true
      sleep 2
    fi
    rm -f "$SERVER_PID_FILE"
  fi

  ensure_pg

  (cd "$REPO_ROOT" && SQLX_OFFLINE=true cargo build -p kota-cli) || return 1

  (
    export DATABASE_URL="${DATABASE_URL:-postgres://user:password@127.0.0.1:${PGPORT:-5441}/${PGDATABASE:-kota}}"
    "$KOTA_BIN" run > "$LOG_FILE" 2>&1 &
    echo "$!" > "$SERVER_PID_FILE"
  )

  # Migrations + job-service init run before the listener opens.
  for _ in {1..60}; do
    if curl -sf "${KOTA_SERVER_URL}/health" >/dev/null 2>&1; then
      echo "--- Server is up ---"
      return 0
    fi
    sleep 1
  done

  echo "server failed to start; log:" >&2
  cat "$LOG_FILE" >&2
  return 1
}

stop_server() {
  if [[ -f "$SERVER_PID_FILE" ]]; then
    kill "$(cat "$SERVER_PID_FILE")" 2>/dev/null || true
    rm -f "$SERVER_PID_FILE"
  fi
}

# --- graphql helpers (lana conventions: .gql files, exec + graphql_output) ---

gql_file() {
  echo "${REPO_ROOT}/bats/gql/$1.gql"
}

gql_operation_name() {
  grep -Eo '(query|mutation) [A-Za-z]+' "$(gql_file "$1")" | head -1 | awk '{print $2}'
}

graphql_payload() {
  jq -n \
    --rawfile query "$(gql_file "$1")" \
    --argjson variables "${2:-{\}}" \
    --arg operationName "$(gql_operation_name "$1")" \
    '{query: $query, variables: $variables, operationName: $operationName}'
}

# exec_graphql <query-name> <user-id> [variables]
exec_graphql() {
  local query_name=$1
  local user_id=$2
  local variables=${3:-"{}"}
  local payload
  payload=$(graphql_payload "$query_name" "$variables")

  if [[ -n "${BATS_TEST_DIRNAME:-}" ]]; then
    run curl -s -X POST \
      -H "Content-Type: application/json" \
      -H "x-user-id: $user_id" \
      -d "$payload" \
      "${GQL_ENDPOINT}"
  else
    output=$(curl -s -X POST \
      -H "Content-Type: application/json" \
      -H "x-user-id: $user_id" \
      -d "$payload" \
      "${GQL_ENDPOINT}")
  fi
}

# Same, without the x-user-id header (auth-rejection tests).
exec_graphql_noauth() {
  local query_name=$1
  local variables=${2:-"{}"}
  local payload
  payload=$(graphql_payload "$query_name" "$variables")

  if [[ -n "${BATS_TEST_DIRNAME:-}" ]]; then
    run curl -s -X POST \
      -H "Content-Type: application/json" \
      -d "$payload" \
      "${GQL_ENDPOINT}"
  else
    output=$(curl -s -X POST \
      -H "Content-Type: application/json" \
      -d "$payload" \
      "${GQL_ENDPOINT}")
  fi
}

graphql_output() {
  jq -r "$1" <<<"$output"
}

# --- flow helpers usable in setup_file (non-`run` branch) ---

# register_wallet <threshold> <participant...> → wallet id
register_wallet() {
  local threshold=$1
  shift
  local participants
  participants=$(printf '"%s",' "$@")
  participants="[${participants%,}]"
  local variables
  variables=$(jq -n --argjson threshold "$threshold" --argjson participants "$participants" \
    '{input: {threshold: $threshold, participants: $participants}}')
  exec_graphql 'wallet-register' "$1" "$variables"
  graphql_output '.data.walletRegister.wallet.walletId'
}

# submit_keystore <wallet-id> <user-id> <keystore>
submit_keystore() {
  local variables
  variables=$(jq -n --arg walletId "$1" --arg keystore "$3" \
    '{input: {walletId: $walletId, keystore: $keystore}}')
  exec_graphql 'wallet-keystore-submit' "$2" "$variables"
  graphql_output '.data.walletKeystoreSubmit.wallet.status'
}
