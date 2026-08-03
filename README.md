# kota

Coordination backend for multi-user bitcoin multisig custody. The platform
never holds key material and never signs — signing happens on each quorum
member's hardware wallet via file/QR-based PSBT exchange. The platform
coordinates the quorum and keeps an immutable audit trail of who did what.

This repo is early scaffolding: one Rust workspace member implementing the
event-sourced PSBT signing-session lifecycle.

## Current state

### `core/coordination` crate

- **`wallet` module** — the `Wallet` aggregate plus wallet-side bitcoin
  logic (descriptor construction, PSBT building). A wallet is *not* born
  with its descriptor: `Initialized` registers only the policy — an
  N-of-M `threshold` over a named set of `participants`, on a network —
  and each participant then submits exactly one keystore
  (`KeystoreAdded`). The aggregate enforces participant binding: a
  non-participant cannot submit, resubmission of the identical key is
  idempotent, a different key requires an explicit `KeystoreRemoved`
  first (pre-activation replacement, e.g. a wrong xpub), and master
  fingerprints must be distinct across participants. The final keystore
  atomically derives the canonical `wsh(sortedmulti(NofM))` descriptor
  (`Activated`). Until then the wallet is `CollectingKeystores` — no
  address space, no spends. A wallet stuck collecting can be abandoned
  (`Cancelled`, pre-activation only; terminal). Wallet identity is two-layered: `WalletId`
  is a framework-internal UUID, while `descriptor_fingerprint` is the
  deterministic content address (SHA-256) of (network, canonical
  descriptor) — NULL until activation, UNIQUE thereafter, so two wallets
  converging on the same descriptor collide at activation and the
  use-case layer turns that into an idempotent find. Descriptors are
  canonicalized at derivation (`sortedmulti_wsh_descriptor` sorts
  keystores) so submission order never affects the fingerprint.
- **`psbt_session` module** — the `PsbtSession` aggregate (`es-entity`):
  - Vocabulary follows Sparrow: a session belongs to a **Wallet** and
    snapshots the wallet's **Policy** (N-of-M `threshold` over
    `keystores`, identified by their master fingerprints) at creation.
    Proposal is gated on the wallet: `NewPsbtSession::try_new` takes
    the `Wallet` aggregate and rejects anything that is not `Active`
    (a wallet still collecting keystores, or a cancelled one, has no
    descriptor and cannot spend). Anyone in the wallet can propose a spend. Actor attribution is split
    by evidence: `proposed_by` is a `UserId` (a platform-attributed
    business fact), while signatures are attributed to keystore
    fingerprints (independently verifiable against the stored PSBT
    blobs). The user ↔ keystore binding is enforced at the use-case
    layer via the future user crate.
  - Proposal and PSBT creation are decoupled: `Initialized` carries a
    denormalized `SpendSpec` (inputs as outpoints, outputs, fee, change)
    and the session starts `Pending`; an async job builds the unsigned
    PSBT from the spec, uploads it to content-addressed storage, and
    appends `PsbtCreated` with the hash — only then does signature
    collection open (`Collecting`). Change is specified as a descriptor
    derivation index, not an address: the job derives the change address
    from the wallet descriptor and fills the PSBT output map, since
    signing devices cannot be relied on to verify multisig change.
  - Events: `Initialized`, `PsbtCreated`, `SignatureAdded`, `Finalized`,
    `BroadcastSeen`, `Confirmed`, `Invalidated`, `Expired`, `Cancelled`.
  - Two causality streams: user commands (signature collection, cancel,
    expire) and chain-sync observations (broadcast/confirm/invalidate),
    kept separate — chain events must match the finalized txid.
  - Reorg-safe: `confirm`/`invalidate` guards use
    `idempotency_guard!(.., resets_on: ..)` so
    `Confirmed → Invalidated → Confirmed` re-executes correctly.
  - Collected ≠ used: over-signing is allowed while collecting; `Finalized`
    records exactly which `sigs_used` authorized the spend.
  - Per-signer idempotent signature upload (guard on signer fingerprint).
  - Policy validity is guaranteed by construction: the snapshot is
    derived from an `Active` wallet, whose own aggregate already
    enforced quorum sanity. Session-level signature-collection
    deadline (`expires_at`).
  - `EsRepo` with a strum↔VARCHAR sqlx shim for the status column.
- **`psbt` module** — `validate_signed_submission`: verifies a
  signer-submitted PSBT is the original unsigned PSBT plus *only* additive
  partial signatures (unsigned tx immutable, no cosigner sigs stripped).
  Two `TODO(security)` items are flagged: binding new signatures to the
  submitter's fingerprint via bip32 key sources, and asserting immutability
  of non-signature PSBT fields.
- **`wallet` module** — the bitcoin-side logic the PSBT-creation job runs:
  `sortedmulti_wsh_descriptor` builds the `wsh(sortedmulti(NofM))`
  descriptor from keystores, `build_unsigned_psbt` constructs the unsigned
  PSBT from a `SpendSpec` + funding UTXOs (validates amounts balance,
  fills `witness_utxo`/`witness_script`/`bip32_derivation` via
  `rust-miniscript`), `descriptor_fingerprints` cross-checks a descriptor
  against a session's policy.
- **`storage` module** — the `BlobStore` content-addressed storage trait
  (`put`/`get`/`delete` by hash) with an `InMemoryBlobStore` for tests;
  GCS/local-filesystem backends to come.
- **`primitives` module** — `entity_id!` ids (`PsbtSessionId`, `WalletId`)
  and `PsbtHash` (SHA-256 content address). PSBT/transaction blobs live in
  dumb content-addressed storage keyed by hash; the event log is the only
  index of which hashes exist and what they mean. Every fetch is
  self-verifying (recompute the digest, compare).

### Persistence

- Migrations: `core_wallets` + `core_wallet_events`,
  `core_psbt_sessions` + `core_psbt_session_events`
  (es-entity conventions).
- `.sqlx/` offline query cache checked in — the workspace compiles without
  a database.

### Tests

- 46 entity unit tests covering the wallet and session state machines,
  idempotency guards, participant binding, keystore replacement, and
  reorg handling — no DB needed.
- 3 end-to-end cryptographic tests (`core/coordination/tests/e2e_signing.rs`)
  running the full flow with real keys: propose -> build unsigned PSBT
  from the spec -> store/fetch by content hash -> sign with a real
  `Xpriv` -> additive-only validation -> finalize -> ECDSA verification
  of the witness against the funding script. Plus negative cases:
  tampered unsigned tx and stripped cosigner signatures are rejected.
- 1 repo round-trip integration test (`core/coordination/tests/`), skipped
  unless `DATABASE_URL` points at a migrated database.

## Development

With nix + direnv (recommended): `direnv allow` drops you into a shell
with the Rust toolchain (from `rust-toolchain.toml`), `sqlx-cli`,
`cargo-nextest`, and postgres, and sets a directory-scoped
`DATABASE_URL`.

```sh
./dev/bin/pg-start.sh           # local postgres on :5441 + migrations (stop: pg-stop.sh)
SQLX_OFFLINE=true cargo test    # all tests, incl. repo round-trip against local pg

cargo sqlx prepare --workspace  # regenerate .sqlx offline cache (needs running pg)
```

Without nix, install the toolchain manually; the integration test skips
itself when `DATABASE_URL` is unset.
