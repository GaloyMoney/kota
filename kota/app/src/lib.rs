//! The kota application layer: use-case commands that drive the
//! `core-coordination` domain.
//!
//! Follows the lana pattern at kota's current scale: a single service
//! struct ([`Coordination`]) holding the repos, the blob store, the job
//! spawners, and module-level config; `init` wires dependencies and
//! registers the job initializers (call before `Jobs::start_poll`);
//! every public operation is an instrumented `async fn`. Subjects are
//! plain [`UserId`]s — *authentication* of the user happens upstream
//! (API layer, future user crate); this layer enforces the structural
//! bindings the aggregates deliberately leave to it:
//!
//! - **user ↔ keystore binding** for signature submission: the
//!   uploader's fingerprint is resolved from the wallet's recorded
//!   submissions, never from client input.
//! - **idempotent wallet import**: two wallets converging on the same
//!   descriptor collide on the UNIQUE fingerprint at activation; the
//!   collision is resolved here to an idempotent find of the existing
//!   wallet.
//!
//! Async work is dispatched to the `job` executor: proposing a spend
//! spawns PSBT creation, and every signature upload spawns
//! finalization (which no-ops below threshold), so the quorum never
//! waits on a polling tick. The job units themselves live in
//! [`core_coordination::jobs`].
//!
//! Lana patterns deliberately *not* adopted yet: `sub: Subject` +
//! authz (needs the user crate), `_in_op` variants (no cross-aggregate
//! transactions exist — every command writes exactly one aggregate),
//! outbox event handlers (chain sync will need one).

mod config;
pub mod error;

pub use config::CoordinationConfig;
pub use error::CoordinationError;

use std::sync::Arc;

use es_entity::clock::ClockHandle;
use miniscript::descriptor::DescriptorPublicKey;
use sqlx::PgPool;
use tracing::instrument;

use core_coordination::jobs::{
    CoordinationJobSpawners, FinalizationJobConfig, FundingUtxoProvider, PsbtCreationJobConfig,
};
use core_coordination::primitives::{DescriptorFingerprint, PsbtSessionId, UserId, WalletId};
use core_coordination::psbt::{merge_partial_sigs, parse_psbt, validate_signed_submission};
use core_coordination::psbt_session::{NewPsbtSession, PsbtSession, PsbtSessionRepo, SpendSpec};
use core_coordination::storage::{BlobStore, fetch_verified};
use core_coordination::wallet::{NewWallet, Wallet, WalletRepo};

/// The coordination service: wallets, signing sessions, and the blobs
/// that pass between signers and platform.
pub struct Coordination<B: BlobStore> {
    wallets: WalletRepo,
    sessions: PsbtSessionRepo,
    blobs: Arc<B>,
    spawners: CoordinationJobSpawners,
    config: CoordinationConfig,
    clock: ClockHandle,
}

impl<B: BlobStore> Clone for Coordination<B> {
    fn clone(&self) -> Self {
        Self {
            wallets: self.wallets.clone(),
            sessions: self.sessions.clone(),
            blobs: self.blobs.clone(),
            spawners: self.spawners.clone(),
            config: self.config.clone(),
            clock: self.clock.clone(),
        }
    }
}

impl<B: BlobStore + Send + Sync + 'static> Coordination<B> {
    /// Wire the service: build the repos, register the job initializers
    /// with `jobs` (lana convention — call before `Jobs::start_poll`).
    /// The executor clock drives the repos, so manual-clock test setups
    /// control everything through `JobSvcConfig::clock`.
    pub fn init<F>(
        pool: &PgPool,
        jobs: &mut job::Jobs,
        blobs: Arc<B>,
        funding: Arc<F>,
        config: CoordinationConfig,
    ) -> Self
    where
        F: FundingUtxoProvider + Send + Sync + 'static,
    {
        let clock = jobs.clock().clone();
        let wallets = WalletRepo::new(pool, clock.clone());
        let sessions = PsbtSessionRepo::new(pool, clock.clone());
        let spawners = core_coordination::jobs::register(
            jobs,
            &sessions,
            &wallets,
            blobs.clone(),
            funding,
            config.network,
        );
        Self {
            wallets,
            sessions,
            blobs,
            spawners,
            config,
            clock,
        }
    }

    // --- wallet lifecycle ---

    /// Register a wallet policy: an N-of-M multisig expecting one
    /// keystore from each participant.
    #[instrument(name = "coordination.register_wallet", skip(self, participants))]
    pub async fn register_wallet(
        &self,
        threshold: u32,
        participants: Vec<UserId>,
    ) -> Result<Wallet, CoordinationError> {
        let new_wallet = NewWallet::new(
            WalletId::new(),
            self.config.network,
            threshold,
            participants,
        )?;
        Ok(self.wallets.create(new_wallet).await?)
    }

    /// Submit a participant's keystore. Idempotent per participant;
    /// activates the wallet when the quorum completes. If activation
    /// collides with an existing wallet on the UNIQUE descriptor
    /// fingerprint (same keys, same network), returns the existing
    /// wallet — importing the same wallet twice is an idempotent find.
    #[instrument(name = "coordination.submit_keystore", skip(self, keystore))]
    pub async fn submit_keystore(
        &self,
        wallet_id: WalletId,
        submitted_by: UserId,
        keystore: DescriptorPublicKey,
    ) -> Result<Wallet, CoordinationError> {
        let mut wallet = self.wallets.find_by_id(wallet_id).await?;
        if wallet
            .add_keystore(keystore, submitted_by)?
            .was_already_applied()
        {
            return Ok(wallet);
        }
        if let Err(e) = self.wallets.update(&mut wallet).await {
            // UNIQUE(descriptor_fingerprint) violation at activation: a
            // concurrent (or previous) import of the same wallet won.
            return self.resolve_fingerprint_collision(wallet, e).await;
        }
        Ok(wallet)
    }

    /// Withdraw a participant's keystore pre-activation so they can
    /// submit a replacement.
    #[instrument(name = "coordination.remove_keystore", skip(self))]
    pub async fn remove_keystore(
        &self,
        wallet_id: WalletId,
        participant: UserId,
        removed_by: UserId,
    ) -> Result<Wallet, CoordinationError> {
        let mut wallet = self.wallets.find_by_id(wallet_id).await?;
        if wallet
            .remove_keystore(participant, removed_by)?
            .was_already_applied()
        {
            return Ok(wallet);
        }
        self.wallets.update(&mut wallet).await?;
        Ok(wallet)
    }

    /// Abandon a wallet that is stuck collecting keystores.
    #[instrument(name = "coordination.cancel_wallet", skip(self, reason))]
    pub async fn cancel_wallet(
        &self,
        wallet_id: WalletId,
        cancelled_by: UserId,
        reason: String,
    ) -> Result<Wallet, CoordinationError> {
        let mut wallet = self.wallets.find_by_id(wallet_id).await?;
        if wallet.cancel(cancelled_by, reason)?.was_already_applied() {
            return Ok(wallet);
        }
        self.wallets.update(&mut wallet).await?;
        Ok(wallet)
    }

    // --- spend lifecycle ---

    /// Propose a spend on an active wallet, then dispatch the
    /// PSBT-creation job. The session starts `Pending`; the job
    /// transitions it to `Collecting` asynchronously.
    #[instrument(name = "coordination.propose_spend", skip(self, spend))]
    pub async fn propose_spend(
        &self,
        wallet_id: WalletId,
        proposed_by: UserId,
        spend: SpendSpec,
    ) -> Result<PsbtSession, CoordinationError> {
        let wallet = self.wallets.find_by_id(wallet_id).await?;
        let new_session =
            NewPsbtSession::try_new(PsbtSessionId::new(), &wallet, proposed_by, spend)?;
        // Session events and the PSBT-creation job row commit
        // atomically: a crash between them would leave the session
        // Pending forever with no job enqueued to build its PSBT.
        let mut op = self.sessions.begin_op().await?;
        let session = self.sessions.create_in_op(&mut op, new_session).await?;
        self.spawners
            .psbt_creation
            .spawn_in_op(
                &mut op,
                job::JobId::new(),
                PsbtCreationJobConfig {
                    session_id: session.id,
                },
            )
            .await?;
        op.commit().await?;
        Ok(session)
    }

    /// The unsigned PSBT bytes a signer downloads to their device,
    /// fetched (and digest-verified) from content-addressed storage.
    #[instrument(name = "coordination.unsigned_psbt", skip(self))]
    pub async fn unsigned_psbt(
        &self,
        session_id: PsbtSessionId,
    ) -> Result<Vec<u8>, CoordinationError> {
        let session = self.sessions.find_by_id(session_id).await?;
        let hash = session
            .unsigned_psbt_hash()
            .ok_or(CoordinationError::UnsignedPsbtNotReady(session_id))?;
        Ok(fetch_verified(self.blobs.as_ref(), &hash).await?)
    }

    /// Submit a signed PSBT on behalf of a participant, then dispatch
    /// the finalization job (a no-op below threshold).
    ///
    /// The signer is *bound* here: the fingerprint attributed to the
    /// signature is resolved from the wallet's recorded submissions for
    /// `submitted_by` — a client cannot claim another keystore's
    /// fingerprint. Validation (additive-only, complete, bound to the
    /// signer's keys, SIGHASH_ALL) happens in `core_coordination::psbt`; only the
    /// extracted signatures, merged onto the original document, are
    /// stored — never the submitted blob itself.
    #[instrument(name = "coordination.submit_signed_psbt", skip(self, signed_psbt))]
    pub async fn submit_signed_psbt(
        &self,
        session_id: PsbtSessionId,
        submitted_by: UserId,
        signed_psbt: &[u8],
    ) -> Result<PsbtSession, CoordinationError> {
        let mut session = self.sessions.find_by_id(session_id).await?;
        // signer ↔ keystore binding: the fingerprint is resolved from
        // the wallet's recorded submissions, never from client input
        let wallet = self.wallets.find_by_id(session.wallet_id).await?;
        let fingerprint = wallet.keystore_fingerprint_of(submitted_by).ok_or(
            CoordinationError::SignerNotBound {
                wallet_id: wallet.id,
                user_id: submitted_by,
            },
        )?;

        let unsigned_hash = session
            .unsigned_psbt_hash()
            .ok_or(CoordinationError::UnsignedPsbtNotReady(session_id))?;
        let original = parse_psbt(&fetch_verified(self.blobs.as_ref(), &unsigned_hash).await?)?;
        let signed = parse_psbt(signed_psbt)?;
        let extracted = validate_signed_submission(&original, &signed, &fingerprint)?;
        let merged = merge_partial_sigs(&original, &extracted);
        let merged_hash = self.blobs.put(&merged.serialize()).await;

        // Signature events and the finalization job row commit
        // atomically: a crash between them could leave a quorum-met
        // session stuck in Collecting with no job ever enqueued. The
        // spawn also runs on idempotent retries — the first attempt may
        // have died before reaching it; the job no-ops when there is
        // nothing to finalize.
        let mut op = self.sessions.begin_op().await?;
        if session
            .add_signature(fingerprint, merged_hash)?
            .did_execute()
        {
            self.sessions.update_in_op(&mut op, &mut session).await?;
        }
        self.spawners
            .finalization
            .spawn_in_op(
                &mut op,
                job::JobId::new(),
                FinalizationJobConfig {
                    session_id: session.id,
                },
            )
            .await?;
        op.commit().await?;
        Ok(session)
    }

    // --- queries ---

    #[instrument(name = "coordination.find_wallet", skip(self))]
    pub async fn find_wallet(&self, wallet_id: WalletId) -> Result<Wallet, CoordinationError> {
        Ok(self.wallets.find_by_id(wallet_id).await?)
    }

    /// `Ok(None)` when no wallet exists for `wallet_id` — the API
    /// layer's `wallet(id)` query maps this to a nullable field.
    #[instrument(name = "coordination.maybe_find_wallet", skip(self))]
    pub async fn maybe_find_wallet(
        &self,
        wallet_id: WalletId,
    ) -> Result<Option<Wallet>, CoordinationError> {
        Ok(self.wallets.maybe_find_by_id(wallet_id).await?)
    }

    /// Idempotent wallet import: look up a wallet by its content
    /// address (network + canonical descriptor).
    #[instrument(name = "coordination.find_wallet_by_fingerprint", skip(self))]
    pub async fn maybe_find_wallet_by_descriptor_fingerprint(
        &self,
        fingerprint: DescriptorFingerprint,
    ) -> Result<Option<Wallet>, CoordinationError> {
        Ok(self
            .wallets
            .maybe_find_by_descriptor_fingerprint(Some(fingerprint))
            .await?)
    }

    #[instrument(name = "coordination.find_session", skip(self))]
    pub async fn find_session(
        &self,
        session_id: PsbtSessionId,
    ) -> Result<PsbtSession, CoordinationError> {
        Ok(self.sessions.find_by_id(session_id).await?)
    }

    /// `Ok(None)` when no session exists for `session_id` — the API
    /// layer's `psbtSession(id)` query maps this to a nullable field.
    #[instrument(name = "coordination.maybe_find_session", skip(self))]
    pub async fn maybe_find_session(
        &self,
        session_id: PsbtSessionId,
    ) -> Result<Option<PsbtSession>, CoordinationError> {
        Ok(self.sessions.maybe_find_by_id(session_id).await?)
    }

    /// A UNIQUE fingerprint collision on update means another wallet
    /// with the same descriptor already exists — return it (idempotent
    /// import). Any other outcome propagates the original error.
    async fn resolve_fingerprint_collision(
        &self,
        wallet: Wallet,
        update_error: impl Into<CoordinationError>,
    ) -> Result<Wallet, CoordinationError> {
        if let Some(fingerprint) = wallet.descriptor_fingerprint()
            && let Ok(existing) = self
                .wallets
                .find_by_descriptor_fingerprint(Some(fingerprint))
                .await
            && existing.id != wallet.id
        {
            return Ok(existing);
        }
        Err(update_error.into())
    }
}
