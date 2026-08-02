# multisig-sig

Coordination backend for multi-user bitcoin multisig custody. The platform
never holds key material and never signs — signing happens on each quorum
member's hardware wallet via file/QR-based PSBT exchange. The platform
coordinates the quorum and keeps an immutable audit trail of who did what.

This repo is early scaffolding: one Rust workspace member implementing the
event-sourced PSBT signing-session lifecycle.

## Current state

### `core/coordination` crate

- **`psbt_session` module** — the `PsbtSession` aggregate (`es-entity`):
  - Events: `Initialized`, `SignatureAdded`, `Finalized`, `BroadcastSeen`,
    `Confirmed`, `Invalidated`, `Expired`, `Cancelled`.
  - Two causality streams: user commands (signature collection, cancel,
    expire) and chain-sync observations (broadcast/confirm/invalidate),
    kept separate — chain events must match the finalized txid.
  - Reorg-safe: `confirm`/`invalidate` guards use
    `idempotency_guard!(.., resets_on: ..)` so
    `Confirmed → Invalidated → Confirmed` re-executes correctly.
  - Collected ≠ used: over-signing is allowed while collecting; `Finalized`
    records exactly which `sigs_used` authorized the spend.
  - Per-signer idempotent signature upload (guard on signer fingerprint).
  - Quorum validated at construction (`QuorumConfig`: threshold, eligible
    signer fingerprints, expiry deadline).
  - `EsRepo` with a strum↔VARCHAR sqlx shim for the status column.
- **`psbt` module** — `validate_signed_submission`: verifies a
  signer-submitted PSBT is the original unsigned PSBT plus *only* additive
  partial signatures (unsigned tx immutable, no cosigner sigs stripped).
  Two `TODO(security)` items are flagged: binding new signatures to the
  submitter's fingerprint via bip32 key sources, and asserting immutability
  of non-signature PSBT fields.
- **`primitives` module** — `entity_id!` ids (`PsbtSessionId`, `VaultId`,
  `ProposalId`), `PsbtHash` (SHA-256 content hash), `BlobRef` (object
  storage reference). PSBT blobs are stored outside the event log; events
  carry ref + hash only.

### Persistence

- Migration: `core_psbt_sessions` + `core_psbt_session_events`
  (es-entity conventions).
- `.sqlx/` offline query cache checked in — the workspace compiles without
  a database.

### Tests

- 15 entity unit tests covering the state machine, idempotency guards,
  quorum validation, and reorg handling — no DB needed.
- 1 repo round-trip integration test (`core/coordination/tests/`), skipped
  unless `DATABASE_URL` points at a migrated database.

## Development

```sh
# needs DATABASE_URL pointing at a postgres for migrate/prepare
sqlx migrate run
cargo sqlx prepare --workspace   # regenerate .sqlx offline cache

SQLX_OFFLINE=true cargo test     # unit tests (no DB needed)
DATABASE_URL=... cargo test      # includes repo round-trip integration test
```

Note: if your shell exports a `DATABASE_URL` for another project, unset it
before running the tests here — the integration test uses whatever it
finds.
