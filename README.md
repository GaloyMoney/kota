# kota

Coordination backend for multi-user bitcoin multisig custody. The platform
never holds key material and never signs — signing happens on each quorum
member's hardware wallet via file/QR-based PSBT exchange. The platform
coordinates the quorum and keeps an immutable audit trail of who did what.

This repo is early scaffolding: the event-sourced PSBT signing-session
lifecycle, laid out lana-style — `core/` domain crates, `kota/` the
application side.

## `core/coordination` — the domain crate

- **`wallet`** — the `Wallet` aggregate (policy registration → keystore
  collection → activation, content-addressed by descriptor fingerprint)
  plus wallet-side bitcoin logic (descriptor construction, PSBT building).
- **`psbt_session`** — the `PsbtSession` aggregate: propose → collect
  signatures → finalize → broadcast → confirm, reorg-safe, with separate
  causality streams for user commands and chain-sync observations.
- **`jobs`** — idempotent async job units (PSBT creation, finalization,
  chain observations) with `job`-crate scheduling adapters.
- **`psbt`** — additive-only validation of signer-submitted PSBTs.
- **`storage`** — content-addressed `BlobStore` trait; in-memory impl for
  tests, GCS/filesystem backends to come.
- **`primitives`** — entity ids and `PsbtHash` (SHA-256 content address).

## `kota/app` — the application crate

The use-case layer (`Coordination` service, lana pattern): commands that
drive the aggregates, spawn the jobs, and enforce the bindings the
aggregates defer (signer ↔ keystore, idempotent wallet import). Sibling
crates to come: `kota/server` (API), `kota/cli`.

Module-level doc comments carry the details; the README stays a map.

## Persistence

- Migrations for the `job` crate tables plus `core_wallets` /
  `core_psbt_sessions` and their event tables (es-entity conventions).
- `.sqlx/` offline query cache checked in — the workspace compiles without
  a database.

## Development

With nix + direnv (recommended): `direnv allow` drops you into a shell
with the Rust toolchain, `sqlx-cli`, and postgres, and sets a
directory-scoped `DATABASE_URL`.

```sh
./dev/bin/pg-start.sh           # local postgres on :5441 + migrations (stop: pg-stop.sh)
                                # PGPORT/PGDATABASE/PGDATA overridable for parallel clones
SQLX_OFFLINE=true cargo test    # unit tests; DB-backed tests skip without DATABASE_URL

cargo sqlx prepare --workspace  # regenerate .sqlx offline cache (needs running pg)
```

Without nix, install the toolchain manually; DB-backed tests skip
themselves when `DATABASE_URL` is unset.
