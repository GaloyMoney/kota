# multisig-sig

Multi-user bitcoin multisig custody **coordination** platform. The platform
never holds key material and never signs — signing happens exclusively on
each quorum member's hardware wallet (file/QR-based PSBT exchange). The
platform coordinates the quorum, enforces policy, and keeps an immutable
audit trail of who did what.

Design rule: **even a fully compromised platform must not be able to steal
funds** — worst case it can grief (hide PSBTs, propose malicious spends that
diligent signers reject on-device, censor).

## Scope decisions (v1)

- File/QR-based signing only (air-gapped PSBT exchange) — no WebHID/USB.
- Plain `wsh(sortedmulti(NofM))` descriptors — no Miniscript yet.
- Bitcoin only, multisig only.

## Architecture

Same stack conventions as lana-bank: Rust + `es-entity` event sourcing,
SQLx (compile-time checked, offline cache in `.sqlx/`), Postgres.

```
core/coordination/
  src/
    primitives.rs          # ids (entity_id!), PsbtHash, BlobRef
    psbt.rs                # security-critical: additive-only signed-PSBT validation
    psbt_session/
      entity.rs            # PsbtSession aggregate (events, commands, queries)
      repo.rs              # EsRepo + strum<->VARCHAR sqlx shim
      primitives.rs        # status machine, InvalidationReason, records
      error.rs             # typed thiserror errors
migrations/                # sqlx migrations
```

### PsbtSession state machine

Two causality streams feed the aggregate; they never mix:

- **User commands**: `Initialized -> SignatureAdded* -> Finalized`,
  plus `Cancelled` (only before broadcast) and `Expired` (platform policy —
  PSBTs don't expire on-chain).
- **Chain sync** (outbox consumer translating bitcoind observations):
  `BroadcastSeen -> Confirmed`, reversible via `Invalidated` (reorg /
  inputs spent externally / RBF replacement). Chain states are never
  terminal — status folds as "latest lifecycle event wins", and commands
  use `idempotency_guard!(.., resets_on: ..)` so re-confirmation after a
  reorg executes as a fresh event.

Key invariants enforced by the entity:

- Per-signer idempotent signature upload (guard on the signer fingerprint).
- Only eligible quorum members can sign; threshold and quorum uniqueness
  validated at construction.
- Collected ≠ used: over-signing is allowed while collecting; `Finalized`
  records exactly which `sigs_used` went into the final transaction.
- Chain events must match the finalized txid.

Enforced by the use-case layer (not the entity):

- `psbt::validate_signed_submission` — a submitted signed PSBT must be the
  original unsigned PSBT plus *only* additive partial signatures (unsigned
  tx immutable, no cosigner sigs stripped). Run before `add_signature`.
- Finalization recomputes the final tx from collected sigs — never trusted
  from a client.

PSBT blobs live in object storage; events carry `BlobRef` + `PsbtHash`
(SHA-256 content hash) as the audit anchor. Blobs get lifecycle controls
(crypto-shredding); the hash-chained event log survives.

## Development

```sh
# needs DATABASE_URL pointing at a postgres for migrate/prepare
sqlx migrate run
cargo sqlx prepare --workspace   # regenerate .sqlx offline cache

SQLX_OFFLINE=true cargo test     # unit tests (no DB needed)
DATABASE_URL=... cargo test      # includes repo round-trip integration test
```
