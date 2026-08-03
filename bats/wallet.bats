#!/usr/bin/env bats

load "helpers"

setup_file() {
  start_server
  for i in 1 2 3; do
    cache_value "participant_$i" "$(random_uuid)"
    cache_value "keystore_$i" "$(gen_keystore "$(random_seed)")"
  done
}

teardown_file() {
  stop_server
}

@test "wallet: register and activate via keystore collection" {
  p1=$(read_value participant_1)
  p2=$(read_value participant_2)
  p3=$(read_value participant_3)

  variables=$(jq -n \
    --argjson threshold 2 \
    --arg p1 "$p1" --arg p2 "$p2" --arg p3 "$p3" \
    '{input: {threshold: $threshold, participants: [$p1, $p2, $p3]}}')
  exec_graphql 'wallet-register' "$p1" "$variables"

  wallet_id=$(graphql_output '.data.walletRegister.wallet.walletId')
  [[ "$wallet_id" != "null" && -n "$wallet_id" ]] || exit 1
  cache_value wallet_id "$wallet_id"
  [[ $(graphql_output '.data.walletRegister.wallet.status') == "COLLECTING_KEYSTORES" ]] || exit 1
  [[ $(graphql_output '.data.walletRegister.wallet.pendingParticipants | length') == "3" ]] || exit 1

  for i in 1 2 3; do
    variables=$(jq -n \
      --arg walletId "$wallet_id" \
      --arg keystore "$(read_value keystore_$i)" \
      '{input: {walletId: $walletId, keystore: $keystore}}')
    exec_graphql 'wallet-keystore-submit' "$(read_value participant_$i)" "$variables"
    [[ $(graphql_output '.errors | length') == "0" ]] || exit 1
  done

  # the third submission completes the quorum and activates the wallet
  [[ $(graphql_output '.data.walletKeystoreSubmit.wallet.status') == "ACTIVE" ]] || exit 1
  descriptor_fingerprint=$(graphql_output '.data.walletKeystoreSubmit.wallet.descriptorFingerprint')
  [[ "$descriptor_fingerprint" != "null" && -n "$descriptor_fingerprint" ]] || exit 1
  cache_value descriptor_fingerprint "$descriptor_fingerprint"

  variables=$(jq -n --arg id "$wallet_id" '{id: $id}')
  exec_graphql 'wallet' "$p1" "$variables"
  [[ $(graphql_output '.data.wallet.status') == "ACTIVE" ]] || exit 1
  [[ $(graphql_output '.data.wallet.descriptor') == wsh\(sortedmulti\(2,* ]] || exit 1
  [[ $(graphql_output '.data.wallet.keystores | length') == "3" ]] || exit 1
  [[ $(graphql_output '.data.wallet.pendingParticipants | length') == "0" ]] || exit 1
}

@test "wallet: keystore resubmission is idempotent" {
  wallet_id=$(read_value wallet_id)
  p1=$(read_value participant_1)

  variables=$(jq -n \
    --arg walletId "$wallet_id" \
    --arg keystore "$(read_value keystore_1)" \
    '{input: {walletId: $walletId, keystore: $keystore}}')
  exec_graphql 'wallet-keystore-submit' "$p1" "$variables"
  [[ $(graphql_output '.errors | length') == "0" ]] || exit 1
  [[ $(graphql_output '.data.walletKeystoreSubmit.wallet.status') == "ACTIVE" ]] || exit 1

  variables=$(jq -n --arg id "$wallet_id" '{id: $id}')
  exec_graphql 'wallet' "$p1" "$variables"
  [[ $(graphql_output '.data.wallet.keystores | length') == "3" ]] || exit 1
}

@test "wallet: importing the same wallet twice is an idempotent find" {
  p1=$(read_value participant_1)
  p2=$(read_value participant_2)
  p3=$(read_value participant_3)
  original_wallet_id=$(read_value wallet_id)

  # same policy, same participants — but a fresh registration
  variables=$(jq -n \
    --argjson threshold 2 \
    --arg p1 "$p1" --arg p2 "$p2" --arg p3 "$p3" \
    '{input: {threshold: $threshold, participants: [$p1, $p2, $p3]}}')
  exec_graphql 'wallet-register' "$p1" "$variables"
  duplicate_id=$(graphql_output '.data.walletRegister.wallet.walletId')
  [[ "$duplicate_id" != "$original_wallet_id" ]] || exit 1

  # the same keystores converge on the same descriptor; the activating
  # submission collides on the UNIQUE fingerprint and resolves to the
  # existing wallet
  for i in 1 2 3; do
    variables=$(jq -n \
      --arg walletId "$duplicate_id" \
      --arg keystore "$(read_value keystore_$i)" \
      '{input: {walletId: $walletId, keystore: $keystore}}')
    exec_graphql 'wallet-keystore-submit' "$(read_value participant_$i)" "$variables"
  done
  [[ $(graphql_output '.data.walletKeystoreSubmit.wallet.walletId') == "$original_wallet_id" ]] || exit 1
  [[ $(graphql_output '.data.walletKeystoreSubmit.wallet.status') == "ACTIVE" ]] || exit 1

  # direct lookup by content address resolves too
  variables=$(jq -n --arg fingerprint "$(read_value descriptor_fingerprint)" '{fingerprint: $fingerprint}')
  exec_graphql 'wallet-by-descriptor-fingerprint' "$p1" "$variables"
  [[ $(graphql_output '.data.walletByDescriptorFingerprint.walletId') == "$original_wallet_id" ]] || exit 1
}

@test "wallet: keystore removal allows replacement pre-activation" {
  p1=$(random_uuid)
  p2=$(random_uuid)
  p3=$(random_uuid)
  keystore_a=$(gen_keystore "$(random_seed)")
  keystore_b=$(gen_keystore "$(random_seed)")

  wallet_id=$(register_wallet 2 "$p1" "$p2" "$p3")
  [[ "$wallet_id" != "null" && -n "$wallet_id" ]] || exit 1
  [[ $(submit_keystore "$wallet_id" "$p1" "$keystore_a") == "COLLECTING_KEYSTORES" ]] || exit 1

  # a different key from the same participant is rejected while the
  # first submission stands
  variables=$(jq -n --arg walletId "$wallet_id" --arg keystore "$keystore_b" \
    '{input: {walletId: $walletId, keystore: $keystore}}')
  exec_graphql 'wallet-keystore-submit' "$p1" "$variables"
  [[ $(graphql_output '.errors | length') -gt 0 ]] || exit 1

  # withdraw, then the replacement is accepted
  variables=$(jq -n --arg walletId "$wallet_id" --arg participant "$p1" \
    '{input: {walletId: $walletId, participant: $participant}}')
  exec_graphql 'wallet-keystore-remove' "$p1" "$variables"
  [[ $(graphql_output '.errors | length') == "0" ]] || exit 1
  [[ $(graphql_output '.data.walletKeystoreRemove.wallet.pendingParticipants | length') == "3" ]] || exit 1

  variables=$(jq -n --arg walletId "$wallet_id" --arg keystore "$keystore_b" \
    '{input: {walletId: $walletId, keystore: $keystore}}')
  exec_graphql 'wallet-keystore-submit' "$p1" "$variables"
  [[ $(graphql_output '.errors | length') == "0" ]] || exit 1
}

@test "wallet: cancel is terminal and idempotent" {
  p1=$(random_uuid)
  p2=$(random_uuid)
  p3=$(random_uuid)

  wallet_id=$(register_wallet 2 "$p1" "$p2" "$p3")
  [[ $(submit_keystore "$wallet_id" "$p1" "$(gen_keystore "$(random_seed)")") == "COLLECTING_KEYSTORES" ]] || exit 1
  cache_value cancelled_wallet_id "$wallet_id"

  variables=$(jq -n --arg walletId "$wallet_id" --arg reason "quorum fell apart" \
    '{input: {walletId: $walletId, reason: $reason}}')
  exec_graphql 'wallet-cancel' "$p1" "$variables"
  [[ $(graphql_output '.data.walletCancel.wallet.status') == "CANCELLED" ]] || exit 1

  # retry after a crash: same outcome, no new event
  variables=$(jq -n --arg walletId "$wallet_id" --arg reason "retry" \
    '{input: {walletId: $walletId, reason: $reason}}')
  exec_graphql 'wallet-cancel' "$p1" "$variables"
  [[ $(graphql_output '.data.walletCancel.wallet.status') == "CANCELLED" ]] || exit 1

  # a cancelled wallet no longer accepts keystores
  variables=$(jq -n --arg walletId "$wallet_id" --arg keystore "$(gen_keystore "$(random_seed)")" \
    '{input: {walletId: $walletId, keystore: $keystore}}')
  exec_graphql 'wallet-keystore-submit' "$p2" "$variables"
  [[ $(graphql_output '.errors | length') -gt 0 ]] || exit 1
}

@test "wallet: requests without a user id are rejected" {
  variables=$(jq -n --arg id "$(read_value wallet_id)" '{id: $id}')
  exec_graphql_noauth 'wallet' "$variables"
  [[ $(graphql_output '.errors | length') -gt 0 ]] || exit 1
  [[ $(graphql_output '.errors[0].message') == "Missing or invalid x-user-id header" ]] || exit 1
}
