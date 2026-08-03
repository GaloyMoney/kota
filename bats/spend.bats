#!/usr/bin/env bats

load "helpers"

# An activated 2-of-3 wallet to propose spends against. The PSBT-
# creation job has no funding source yet (chain sync is not built), so
# sessions stay Pending — this file covers the API surface up to that
# boundary.
setup_file() {
  start_server
  for i in 1 2 3; do
    cache_value "spend_participant_$i" "$(random_uuid)"
    cache_value "spend_keystore_$i" "$(gen_keystore "$(random_seed)")"
  done

  p1=$(read_value spend_participant_1)
  p2=$(read_value spend_participant_2)
  p3=$(read_value spend_participant_3)
  wallet_id=$(register_wallet 2 "$p1" "$p2" "$p3")
  for i in 1 2 3; do
    status=$(submit_keystore "$wallet_id" "$(read_value spend_participant_$i)" "$(read_value spend_keystore_$i)")
  done
  if [[ "$status" != "ACTIVE" ]]; then
    echo "setup_file: wallet did not activate (last status: $status)" >&2
    return 1
  fi
  cache_value spend_wallet_id "$wallet_id"
}

teardown_file() {
  stop_server
}

TXID="0707070707070707070707070707070707070707070707070707070707070707"
ADDRESS="bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"

spend_variables() {
  jq -n \
    --arg walletId "$(read_value spend_wallet_id)" \
    --arg txid "$TXID" \
    --arg address "$ADDRESS" \
    '{input: {
      walletId: $walletId,
      inputs: [{txid: $txid, vout: 0}],
      outputs: [{address: $address, amountSats: 50000}],
      feeSats: 500
    }}'
}

@test "spend: propose on an active wallet yields a pending session" {
  p1=$(read_value spend_participant_1)

  exec_graphql 'spend-propose' "$p1" "$(spend_variables)"
  [[ $(graphql_output '.errors | length') == "0" ]] || exit 1

  session_id=$(graphql_output '.data.spendPropose.psbtSession.psbtSessionId')
  [[ "$session_id" != "null" && -n "$session_id" ]] || exit 1
  cache_value session_id "$session_id"
  [[ $(graphql_output '.data.spendPropose.psbtSession.status') == "PENDING" ]] || exit 1
  [[ $(graphql_output '.data.spendPropose.psbtSession.proposedBy') == "$p1" ]] || exit 1
  [[ $(graphql_output '.data.spendPropose.psbtSession.walletId') == "$(read_value spend_wallet_id)" ]] || exit 1
  [[ $(graphql_output '.data.spendPropose.psbtSession.threshold') == "2" ]] || exit 1
  [[ $(graphql_output '.data.spendPropose.psbtSession.inputs[0].txid') == "$TXID" ]] || exit 1
  [[ $(graphql_output '.data.spendPropose.psbtSession.outputs[0].amountSats') == "50000" ]] || exit 1
}

@test "spend: session query exposes the collection state" {
  p1=$(read_value spend_participant_1)
  session_id=$(read_value session_id)

  variables=$(jq -n --arg id "$session_id" '{id: $id}')
  exec_graphql 'psbt-session' "$p1" "$variables"
  [[ $(graphql_output '.errors | length') == "0" ]] || exit 1
  [[ $(graphql_output '.data.psbtSession.status') == "PENDING" ]] || exit 1
  [[ $(graphql_output '.data.psbtSession.signatureCount') == "0" ]] || exit 1
  [[ $(graphql_output '.data.psbtSession.thresholdMet') == "false" ]] || exit 1
  # the PSBT-creation job has no funding source yet, so nothing to sign
  [[ $(graphql_output '.data.psbtSession.unsignedPsbtHash') == "null" ]] || exit 1
  [[ $(graphql_output '.data.psbtSession.unsignedPsbt') == "null" ]] || exit 1
  [[ $(graphql_output '.data.psbtSession.missingKeystores | length') == "3" ]] || exit 1
  [[ $(graphql_output '.data.psbtSession.finalization') == "null" ]] || exit 1
}

@test "spend: signature upload is rejected before the unsigned PSBT exists" {
  p1=$(read_value spend_participant_1)
  session_id=$(read_value session_id)

  # any base64 blob will do — the app layer rejects on
  # UnsignedPsbtNotReady before parsing
  signed_psbt=$(printf 'not-a-real-psbt' | base64)
  variables=$(jq -n --arg sessionId "$session_id" --arg signedPsbt "$signed_psbt" \
    '{input: {sessionId: $sessionId, signedPsbt: $signedPsbt}}')
  exec_graphql 'signed-psbt-submit' "$p1" "$variables"
  [[ $(graphql_output '.errors | length') -gt 0 ]] || exit 1
  [[ $(graphql_output '.data.signedPsbtSubmit') == "null" ]] || exit 1
}

@test "spend: propose on a non-active wallet is rejected" {
  p1=$(random_uuid)
  p2=$(random_uuid)
  p3=$(random_uuid)
  wallet_id=$(register_wallet 2 "$p1" "$p2" "$p3")
  [[ "$wallet_id" != "null" && -n "$wallet_id" ]] || exit 1

  variables=$(jq -n \
    --arg walletId "$wallet_id" \
    --arg txid "$TXID" \
    --arg address "$ADDRESS" \
    '{input: {
      walletId: $walletId,
      inputs: [{txid: $txid, vout: 0}],
      outputs: [{address: $address, amountSats: 50000}],
      feeSats: 500
    }}')
  exec_graphql 'spend-propose' "$p1" "$variables"
  [[ $(graphql_output '.errors | length') -gt 0 ]] || exit 1
  [[ $(graphql_output '.data.spendPropose') == "null" ]] || exit 1
}

@test "spend: malformed input is rejected at the boundary" {
  p1=$(read_value spend_participant_1)

  # bad txid
  variables=$(jq -n \
    --arg walletId "$(read_value spend_wallet_id)" \
    --arg address "$ADDRESS" \
    '{input: {
      walletId: $walletId,
      inputs: [{txid: "not-a-txid", vout: 0}],
      outputs: [{address: $address, amountSats: 50000}],
      feeSats: 500
    }}')
  exec_graphql 'spend-propose' "$p1" "$variables"
  [[ $(graphql_output '.errors | length') -gt 0 ]] || exit 1

  # bad address
  variables=$(jq -n \
    --arg walletId "$(read_value spend_wallet_id)" \
    --arg txid "$TXID" \
    '{input: {
      walletId: $walletId,
      inputs: [{txid: $txid, vout: 0}],
      outputs: [{address: "not-an-address", amountSats: 50000}],
      feeSats: 500
    }}')
  exec_graphql 'spend-propose' "$p1" "$variables"
  [[ $(graphql_output '.errors | length') -gt 0 ]] || exit 1

  # bad keystore encoding
  variables=$(jq -n --arg walletId "$(read_value spend_wallet_id)" \
    '{input: {walletId: $walletId, keystore: "not-a-keystore"}}')
  exec_graphql 'wallet-keystore-submit' "$p1" "$variables"
  [[ $(graphql_output '.errors | length') -gt 0 ]] || exit 1
}
