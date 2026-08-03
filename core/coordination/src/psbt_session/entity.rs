use derive_builder::Builder;
use serde::{Deserialize, Serialize};

use es_entity::*;

use bitcoin::{
    Amount, BlockHash, ScriptBuf, Txid, WScriptHash, bip32::Fingerprint as KeyFingerprint,
};

use crate::primitives::{PsbtHash, PsbtSessionId, UserId, WalletId};
use crate::wallet::{Wallet, WalletStatus, keystore_fingerprint};

use super::error::PsbtSessionError;
use super::primitives::{
    ChangeOutput, FinalizationRecord, InvalidationReason, OutPointRef, PsbtSessionStatus,
    SignatureRecord, SpendOutput,
};

#[derive(EsEvent, Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[es_event(id = "PsbtSessionId")]
pub enum PsbtSessionEvent {
    Initialized {
        id: PsbtSessionId,
        wallet_id: WalletId,
        /// User who proposed this spend. Anyone in the wallet can propose.
        /// This is a platform-attributed business fact (no cryptographic
        /// evidence exists for it) — unlike signatures, which are
        /// attributed to keystores and are independently verifiable
        /// against the stored PSBT blobs. The user ↔ keystore binding is
        /// enforced by the use-case layer via the (future) user crate.
        proposed_by: UserId,
        /// Denormalized summary of the spend, extracted and validated at
        /// the use-case layer. The PSBT built from this data (see
        /// `PsbtCreated`) is the cryptographic source of truth.
        inputs: Vec<OutPointRef>,
        outputs: Vec<SpendOutput>,
        fee_sats: u64,
        change_output: Option<ChangeOutput>,
        threshold: u32,
        keystores: Vec<KeyFingerprint>,
    },
    /// The async PSBT-creation job built the unsigned PSBT from the
    /// `Initialized` data and uploaded it to content-addressed storage.
    /// Transitions the session from Pending to Collecting.
    PsbtCreated {
        unsigned_psbt_hash: PsbtHash,
    },
    /// A signer submitted a signed PSBT that passed additive-only
    /// validation (see `crate::psbt`). Collected ≠ used: more signatures
    /// than the threshold may be collected.
    SignatureAdded {
        fingerprint: KeyFingerprint,
        signed_psbt_hash: PsbtHash,
    },
    /// The final transaction was *recomputed* by the platform from the
    /// collected partial signatures. `sigs_used` is the audit answer to
    /// "whose signature authorized this spend?".
    Finalized {
        txid: Txid,
        final_tx_hash: PsbtHash,
        sigs_used: Vec<KeyFingerprint>,
    },
    /// Chain sync observed the finalized tx in the mempool / a block.
    BroadcastSeen {
        txid: Txid,
    },
    Confirmed {
        txid: Txid,
        height: u64,
        block_hash: BlockHash,
    },
    /// Chain-observed reversal — reorg, external spend of inputs, RBF
    /// replacement. Chain states are never terminal.
    Invalidated {
        reason: InvalidationReason,
    },
    Cancelled {
        reason: String,
    },
}

#[derive(EsEntity, Builder)]
#[builder(pattern = "owned", build_fn(error = "EntityHydrationError"))]
pub struct PsbtSession {
    pub id: PsbtSessionId,
    pub wallet_id: WalletId,
    pub proposed_by: UserId,
    pub inputs: Vec<OutPointRef>,
    pub outputs: Vec<SpendOutput>,
    pub fee_sats: u64,
    pub change_output: Option<ChangeOutput>,
    #[builder(setter(strip_option), default)]
    unsigned_psbt_hash: Option<PsbtHash>,
    threshold: u32,
    keystores: Vec<KeyFingerprint>,
    signatures: Vec<SignatureRecord>,
    #[builder(setter(strip_option), default)]
    finalization: Option<FinalizationRecord>,
    events: EntityEvents<PsbtSessionEvent>,
}

impl PsbtSession {
    /// Latest lifecycle event wins. Chain-observed states are reversible:
    /// `Confirmed` → `Invalidated` (reorg) → `Confirmed` (re-confirmed in
    /// the new best chain) all reflect correctly.
    pub fn status(&self) -> PsbtSessionStatus {
        for event in self.events.iter_all().rev() {
            match event {
                PsbtSessionEvent::Cancelled { .. } => return PsbtSessionStatus::Cancelled,
                PsbtSessionEvent::Confirmed { .. } => return PsbtSessionStatus::Confirmed,
                PsbtSessionEvent::Invalidated { .. } => return PsbtSessionStatus::Invalidated,
                PsbtSessionEvent::BroadcastSeen { .. } => return PsbtSessionStatus::Broadcast,
                PsbtSessionEvent::Finalized { .. } => return PsbtSessionStatus::Finalized,
                PsbtSessionEvent::PsbtCreated { .. } => return PsbtSessionStatus::Collecting,
                _ => {}
            }
        }
        PsbtSessionStatus::Pending
    }

    /// Content address of the unsigned PSBT, once the creation job ran.
    pub fn unsigned_psbt_hash(&self) -> Option<PsbtHash> {
        self.unsigned_psbt_hash
    }

    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    pub fn keystores(&self) -> &[KeyFingerprint] {
        &self.keystores
    }

    pub fn signatures(&self) -> &[SignatureRecord] {
        &self.signatures
    }

    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }

    pub fn threshold_met(&self) -> bool {
        self.signatures.len() >= self.threshold as usize
    }

    pub fn missing_keystores(&self) -> Vec<KeyFingerprint> {
        self.keystores
            .iter()
            .filter(|fp| !self.has_signed(fp))
            .copied()
            .collect()
    }

    pub fn finalization(&self) -> Option<&FinalizationRecord> {
        self.finalization.as_ref()
    }

    fn is_collecting(&self) -> bool {
        self.status() == PsbtSessionStatus::Collecting
    }

    fn has_signed(&self, fingerprint: &KeyFingerprint) -> bool {
        self.signatures
            .iter()
            .any(|s| s.fingerprint == *fingerprint)
    }

    /// Record the unsigned PSBT built by the async creation job.
    ///
    /// The job reads the `Initialized` data (inputs/outputs/fee/change),
    /// builds the PSBT, uploads it to content-addressed storage, then
    /// calls this with the resulting hash. Transitions the session from
    /// Pending to Collecting — signatures are not accepted before this.
    pub fn record_psbt_created(
        &mut self,
        unsigned_psbt_hash: PsbtHash,
    ) -> Result<Idempotent<()>, PsbtSessionError> {
        idempotency_guard!(
            self.events.iter_all().rev(),
            already_applied: PsbtSessionEvent::PsbtCreated { .. },
        );
        if self.status() != PsbtSessionStatus::Pending {
            return Err(PsbtSessionError::CannotAttachPsbt {
                id: self.id,
                status: self.status(),
            });
        }

        self.unsigned_psbt_hash = Some(unsigned_psbt_hash);
        self.events
            .push(PsbtSessionEvent::PsbtCreated { unsigned_psbt_hash });
        Ok(Idempotent::Executed(()))
    }

    /// Record a validated signed-PSBT submission.
    ///
    /// The use-case layer MUST run `crate::psbt::validate_signed_submission`
    /// (with the uploader's authenticated keystore fingerprint) against the
    /// original unsigned PSBT and the submitted blob, then persist the
    /// result of `crate::psbt::merge_partial_sigs` — the original document
    /// plus the extracted signatures — and pass *that* blob's hash as
    /// `signed_psbt_hash`. The entity only enforces policy membership and
    /// lifecycle state. Validation also enforces completeness (every input
    /// signed) — the first upload per fingerprint is final, so a
    /// partially-signed PSBT must never be accepted.
    ///
    /// Idempotent per signer: re-uploading after a crash/retry is a no-op.
    pub fn add_signature(
        &mut self,
        fingerprint: KeyFingerprint,
        signed_psbt_hash: PsbtHash,
    ) -> Result<Idempotent<()>, PsbtSessionError> {
        idempotency_guard!(
            self.events.iter_all().rev(),
            already_applied: PsbtSessionEvent::SignatureAdded { fingerprint: fp, .. } if *fp == fingerprint,
        );
        if !self.is_collecting() {
            return Err(PsbtSessionError::NotCollecting(self.id));
        }
        if !self.keystores.contains(&fingerprint) {
            return Err(PsbtSessionError::UnknownKeystore(fingerprint));
        }

        self.signatures.push(SignatureRecord {
            fingerprint,
            signed_psbt_hash,
        });
        self.events.push(PsbtSessionEvent::SignatureAdded {
            fingerprint,
            signed_psbt_hash,
        });
        Ok(Idempotent::Executed(()))
    }

    /// Finalize at or above threshold. Triggered by the jobs layer once
    /// `threshold_met()`; the final tx is recomputed from collected sigs by
    /// the caller — never trusted from a client.
    pub fn finalize(
        &mut self,
        txid: Txid,
        final_tx_hash: PsbtHash,
        mut sigs_used: Vec<KeyFingerprint>,
    ) -> Result<Idempotent<Txid>, PsbtSessionError> {
        idempotency_guard!(
            self.events.iter_all().rev(),
            already_applied: PsbtSessionEvent::Finalized { .. },
        );
        if !self.is_collecting() {
            return Err(PsbtSessionError::NotCollecting(self.id));
        }
        if sigs_used.len() < self.threshold as usize {
            return Err(PsbtSessionError::ThresholdNotMet {
                collected: sigs_used.len(),
                threshold: self.threshold,
            });
        }
        {
            let mut dedup = sigs_used.clone();
            dedup.sort();
            dedup.dedup();
            if dedup.len() != sigs_used.len() {
                return Err(PsbtSessionError::DuplicateSigsUsed);
            }
            sigs_used = dedup;
        }
        if !sigs_used.iter().all(|fp| self.has_signed(fp)) {
            return Err(PsbtSessionError::SigsUsedNotCollected);
        }

        self.finalization = Some(FinalizationRecord {
            txid,
            final_tx_hash,
            sigs_used: sigs_used.clone(),
        });
        self.events.push(PsbtSessionEvent::Finalized {
            txid,
            final_tx_hash,
            sigs_used,
        });
        Ok(Idempotent::Executed(txid))
    }

    /// Chain sync observed the tx. Delivered via the outbox consumer, not a
    /// user command — chain events never assert user intent.
    pub fn mark_broadcast_seen(&mut self, txid: Txid) -> Result<Idempotent<()>, PsbtSessionError> {
        let finalization = self
            .finalization
            .as_ref()
            .ok_or(PsbtSessionError::NotFinalized(self.id))?;
        if finalization.txid != txid {
            return Err(PsbtSessionError::TxidMismatch);
        }
        idempotency_guard!(
            self.events.iter_all().rev(),
            already_applied: PsbtSessionEvent::BroadcastSeen { .. },
        );
        // A `Confirmed` may already have arrived during catch-up sync; the
        // mempool sighting is then safely redundant.
        if self.status() == PsbtSessionStatus::Confirmed {
            return Ok(Idempotent::AlreadyApplied);
        }

        self.events.push(PsbtSessionEvent::BroadcastSeen { txid });
        Ok(Idempotent::Executed(()))
    }

    pub fn confirm(
        &mut self,
        txid: Txid,
        height: u64,
        block_hash: BlockHash,
    ) -> Result<Idempotent<()>, PsbtSessionError> {
        let finalization = self
            .finalization
            .as_ref()
            .ok_or(PsbtSessionError::NotFinalized(self.id))?;
        if finalization.txid != txid {
            return Err(PsbtSessionError::TxidMismatch);
        }
        idempotency_guard!(
            self.events.iter_all().rev(),
            already_applied: PsbtSessionEvent::Confirmed { .. },
            resets_on: PsbtSessionEvent::Invalidated { .. },
        );

        self.events.push(PsbtSessionEvent::Confirmed {
            txid,
            height,
            block_hash,
        });
        Ok(Idempotent::Executed(()))
    }

    /// Chain sync observed a reversal (reorg / external spend / RBF).
    pub fn invalidate(
        &mut self,
        reason: InvalidationReason,
    ) -> Result<Idempotent<()>, PsbtSessionError> {
        idempotency_guard!(
            self.events.iter_all().rev(),
            already_applied: PsbtSessionEvent::Invalidated { .. },
            resets_on: PsbtSessionEvent::Confirmed { .. },
        );
        match self.status() {
            PsbtSessionStatus::Broadcast | PsbtSessionStatus::Confirmed => {}
            status => {
                return Err(PsbtSessionError::CannotInvalidate {
                    id: self.id,
                    status,
                });
            }
        }

        self.events.push(PsbtSessionEvent::Invalidated { reason });
        Ok(Idempotent::Executed(()))
    }

    /// Cancellation is only meaningful before broadcast — once the tx is
    /// out, the chain decides. `Finalized` is still cancellable ("do not
    /// broadcast, abandon"), as is a `Pending` session whose PSBT
    /// creation is stuck.
    pub fn cancel(&mut self, reason: String) -> Result<Idempotent<()>, PsbtSessionError> {
        idempotency_guard!(
            self.events.iter_all().rev(),
            already_applied: PsbtSessionEvent::Cancelled { .. },
        );
        match self.status() {
            PsbtSessionStatus::Pending
            | PsbtSessionStatus::Collecting
            | PsbtSessionStatus::Finalized => {}
            status => {
                return Err(PsbtSessionError::CannotCancel {
                    id: self.id,
                    status,
                });
            }
        }

        self.events.push(PsbtSessionEvent::Cancelled { reason });
        Ok(Idempotent::Executed(()))
    }
}

impl TryFromEvents<PsbtSessionEvent> for PsbtSession {
    fn try_from_events(
        events: EntityEvents<PsbtSessionEvent>,
    ) -> Result<Self, EntityHydrationError> {
        let mut builder = PsbtSessionBuilder::default();
        let mut signatures = Vec::new();
        for event in events.iter_all() {
            match event {
                PsbtSessionEvent::Initialized {
                    id,
                    wallet_id,
                    proposed_by,
                    inputs,
                    outputs,
                    fee_sats,
                    change_output,
                    threshold,
                    keystores,
                } => {
                    builder = builder
                        .id(*id)
                        .wallet_id(*wallet_id)
                        .proposed_by(*proposed_by)
                        .inputs(inputs.clone())
                        .outputs(outputs.clone())
                        .fee_sats(*fee_sats)
                        .change_output(change_output.clone())
                        .threshold(*threshold)
                        .keystores(keystores.clone());
                }
                PsbtSessionEvent::PsbtCreated { unsigned_psbt_hash } => {
                    builder = builder.unsigned_psbt_hash(*unsigned_psbt_hash);
                }
                PsbtSessionEvent::SignatureAdded {
                    fingerprint,
                    signed_psbt_hash,
                } => {
                    signatures.push(SignatureRecord {
                        fingerprint: *fingerprint,
                        signed_psbt_hash: *signed_psbt_hash,
                    });
                }
                PsbtSessionEvent::Finalized {
                    txid,
                    final_tx_hash,
                    sigs_used,
                } => {
                    builder = builder.finalization(FinalizationRecord {
                        txid: *txid,
                        final_tx_hash: *final_tx_hash,
                        sigs_used: sigs_used.clone(),
                    });
                }
                PsbtSessionEvent::BroadcastSeen { .. }
                | PsbtSessionEvent::Confirmed { .. }
                | PsbtSessionEvent::Invalidated { .. }
                | PsbtSessionEvent::Cancelled { .. } => {}
            }
        }
        builder.signatures(signatures).events(events).build()
    }
}

/// What the spend moves: coins consumed, destinations, fee, and change.
/// The async PSBT-creation job builds the unsigned PSBT from this spec.
#[derive(Debug, Clone)]
pub struct SpendSpec {
    pub inputs: Vec<OutPointRef>,
    pub outputs: Vec<SpendOutput>,
    pub fee_sats: u64,
    pub change_output: Option<ChangeOutput>,
}

/// Hard cap on the fee a proposal may declare, in sats (0.01 BTC).
///
/// Signers verify the spend on their hardware wallets, but a
/// fat-fingered or malicious proposer (anyone in the wallet can
/// propose) should not be able to put an absurd fee in front of the
/// quorum at all. Absolute cap rather than a feerate: the proposal
/// layer does not know input amounts or tx vsize — the PSBT-creation
/// job additionally enforces exact balance (inputs == outputs + fee),
/// and signers see the implied feerate on-device.
pub const MAX_FEE_SATS: u64 = 1_000_000;

/// Dust threshold for the wallet's change outputs. Change is always
/// P2WSH (derived from the `wsh(sortedmulti)` descriptor by the
/// creation job), so the bound is computable at proposal time from a
/// representative script — dust depends only on the script's
/// serialized size, not its content.
fn p2wsh_dust_threshold() -> Amount {
    use bitcoin::hashes::Hash;
    ScriptBuf::new_p2wsh(&WScriptHash::from_byte_array([0; 32])).minimal_non_dust()
}

#[derive(Debug, Builder)]
pub struct NewPsbtSession {
    #[builder(setter(into))]
    pub(super) id: PsbtSessionId,
    wallet_id: WalletId,
    proposed_by: UserId,
    inputs: Vec<OutPointRef>,
    outputs: Vec<SpendOutput>,
    fee_sats: u64,
    change_output: Option<ChangeOutput>,
    threshold: u32,
    keystores: Vec<KeyFingerprint>,
}

impl NewPsbtSession {
    pub fn builder() -> NewPsbtSessionBuilder {
        NewPsbtSessionBuilder::default()
    }

    /// Propose a spend on `wallet`.
    ///
    /// The wallet must be `Active` — a wallet still collecting
    /// keystores (or a cancelled one) has no descriptor and cannot
    /// spend. The wallet's signing policy (Sparrow vocabulary: N-of-M
    /// `threshold` over the wallet's `keystores`, identified by master
    /// fingerprint) is *snapshotted* into the session at creation, so
    /// the session pins the exact key set its signatures are validated
    /// against even if wallet membership were to change later.
    pub fn try_new(
        id: PsbtSessionId,
        wallet: &Wallet,
        proposed_by: UserId,
        spend: SpendSpec,
    ) -> Result<Self, PsbtSessionError> {
        if wallet.status() != WalletStatus::Active {
            return Err(PsbtSessionError::WalletNotActive {
                wallet_id: wallet.id,
                status: wallet.status(),
            });
        }
        let wallet_id = wallet.id;
        let threshold = wallet.threshold;
        let keystores = wallet
            .keystores()
            .iter()
            .map(keystore_fingerprint)
            .collect::<Vec<_>>();
        let SpendSpec {
            inputs,
            outputs,
            fee_sats,
            change_output,
        } = spend;
        if inputs.is_empty() {
            return Err(PsbtSessionError::EmptyInputs);
        }
        {
            let mut dedup = inputs.clone();
            dedup.sort();
            let window = dedup.windows(2).find(|w| w[0] == w[1]);
            if let Some(w) = window {
                return Err(PsbtSessionError::DuplicateInput {
                    txid: w[0].txid,
                    vout: w[0].vout,
                });
            }
        }
        if outputs.is_empty() {
            return Err(PsbtSessionError::EmptyOutputs);
        }
        // The wallet's network is known at proposal time, so a
        // wrong-network destination is rejected here — not left for the
        // PSBT-creation job to discover after the fact, where it would
        // fail permanently on a session that can no longer be fixed.
        // (`build_unsigned_psbt` re-checks as defense-in-depth.)
        for output in &outputs {
            let address = output
                .address
                .clone()
                .require_network(wallet.network)
                .map_err(|e| PsbtSessionError::InvalidAddress {
                    network: wallet.network,
                    reason: e.to_string(),
                })?;
            // A zero or sub-dust output makes the whole transaction
            // non-standard: it would build and finalize fine and then
            // never relay, stranding the session past finalization.
            // The dust threshold is script-dependent and knowable at
            // proposal time.
            let dust = address.script_pubkey().minimal_non_dust();
            if Amount::from_sat(output.amount_sats) < dust {
                return Err(PsbtSessionError::DustOutput {
                    amount_sats: output.amount_sats,
                    dust_sats: dust.to_sat(),
                });
            }
        }
        // Change is always P2WSH (derived from the wsh(sortedmulti)
        // descriptor by the creation job), so its dust bound is known
        // here too — sub-dust change must be folded into the fee by the
        // proposer, not emitted as an unspendable output.
        if let Some(change) = &change_output {
            let dust = p2wsh_dust_threshold();
            if Amount::from_sat(change.amount_sats) < dust {
                return Err(PsbtSessionError::DustOutput {
                    amount_sats: change.amount_sats,
                    dust_sats: dust.to_sat(),
                });
            }
        }
        if fee_sats > MAX_FEE_SATS {
            return Err(PsbtSessionError::FeeExceedsMax {
                fee_sats,
                max_sats: MAX_FEE_SATS,
            });
        }
        debug_assert!(
            threshold > 0 && threshold as usize <= keystores.len(),
            "an active wallet's policy is valid by construction"
        );

        Ok(Self {
            id,
            wallet_id,
            proposed_by,
            inputs,
            outputs,
            fee_sats,
            change_output,
            threshold,
            keystores,
        })
    }

    pub(super) fn wallet_id(&self) -> WalletId {
        self.wallet_id
    }

    pub(super) fn status(&self) -> PsbtSessionStatus {
        PsbtSessionStatus::Pending
    }
}

impl IntoEvents<PsbtSessionEvent> for NewPsbtSession {
    fn into_events(self) -> EntityEvents<PsbtSessionEvent> {
        EntityEvents::init(
            self.id,
            [PsbtSessionEvent::Initialized {
                id: self.id,
                wallet_id: self.wallet_id,
                proposed_by: self.proposed_by,
                inputs: self.inputs,
                outputs: self.outputs,
                fee_sats: self.fee_sats,
                change_output: self.change_output,
                threshold: self.threshold,
                keystores: self.keystores,
            }],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;
    use bitcoin::hashes::Hash;

    use crate::wallet::{NewWallet, tests::keystore as wallet_keystore};

    fn fp(byte: u8) -> KeyFingerprint {
        keystore_fingerprint(&wallet_keystore(byte))
    }

    fn wallet_with_keystores(threshold: u32, seeds: &[u8]) -> (Wallet, Vec<UserId>) {
        let participants: Vec<UserId> = seeds.iter().map(|_| UserId::new()).collect();
        let mut wallet = Wallet::try_from_events(
            NewWallet::new(
                WalletId::new(),
                Network::Regtest,
                threshold,
                participants.clone(),
            )
            .unwrap()
            .into_events(),
        )
        .unwrap();
        for (seed, participant) in seeds.iter().zip(&participants) {
            let _ = wallet
                .add_keystore(wallet_keystore(*seed), *participant)
                .unwrap();
        }
        (wallet, participants)
    }

    fn active_wallet(threshold: u32, seeds: &[u8]) -> Wallet {
        wallet_with_keystores(threshold, seeds).0
    }

    fn dummy_txid(byte: u8) -> Txid {
        Txid::from_byte_array([byte; 32])
    }

    fn dummy_block_hash(byte: u8) -> BlockHash {
        BlockHash::from_byte_array([byte; 32])
    }

    fn sample_spend() -> SpendSpec {
        SpendSpec {
            inputs: vec![OutPointRef {
                txid: dummy_txid(100),
                vout: 0,
            }],
            outputs: vec![SpendOutput {
                // regtest HRP of the BIP-173 example witness program —
                // proposal validates output addresses against the wallet's
                // network, and the fixture wallet is on regtest
                address: "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
                    .parse()
                    .unwrap(),
                amount_sats: 50_000,
            }],
            fee_sats: 500,
            change_output: Some(ChangeOutput {
                amount_sats: 10_000,
                derivation_index: 1,
            }),
        }
    }

    fn unsigned_psbt_hash() -> PsbtHash {
        PsbtHash::digest_of(b"unsigned-psbt")
    }

    fn propose(wallet: &Wallet, spend: SpendSpec) -> Result<NewPsbtSession, PsbtSessionError> {
        NewPsbtSession::try_new(PsbtSessionId::new(), wallet, UserId::new(), spend)
    }

    /// A freshly proposed session: Pending, no PSBT yet.
    fn create_session() -> PsbtSession {
        let wallet = active_wallet(2, &[1, 2, 3]);
        PsbtSession::try_from_events(propose(&wallet, sample_spend()).unwrap().into_events())
            .unwrap()
    }

    /// A session whose PSBT-creation job has run: Collecting.
    fn create_collecting_session() -> PsbtSession {
        let mut session = create_session();
        let _ = session.record_psbt_created(unsigned_psbt_hash()).unwrap();
        session
    }

    fn add_sig(session: &mut PsbtSession, byte: u8) -> Result<Idempotent<()>, PsbtSessionError> {
        session.add_signature(
            fp(byte),
            PsbtHash::digest_of(format!("signed-psbt-{byte}").as_bytes()),
        )
    }

    fn finalize(session: &mut PsbtSession, sigs_used: Vec<KeyFingerprint>) {
        let _ = session
            .finalize(dummy_txid(1), PsbtHash::digest_of(b"final-tx"), sigs_used)
            .unwrap();
    }

    #[test]
    fn new_session_is_pending() {
        let session = create_session();
        assert_eq!(session.status(), PsbtSessionStatus::Pending);
        assert_eq!(session.unsigned_psbt_hash(), None);
        assert_eq!(session.signature_count(), 0);
        assert!(!session.threshold_met());
        assert_eq!(session.missing_keystores(), vec![fp(1), fp(2), fp(3)]);
        assert_eq!(session.inputs, sample_spend().inputs);
        assert_eq!(session.outputs, sample_spend().outputs);
        assert_eq!(session.fee_sats, 500);
        assert_eq!(session.change_output, sample_spend().change_output);
    }

    #[test]
    fn psbt_created_transitions_to_collecting() {
        let mut session = create_session();
        assert!(
            session
                .record_psbt_created(unsigned_psbt_hash())
                .unwrap()
                .did_execute()
        );
        assert_eq!(session.status(), PsbtSessionStatus::Collecting);
        assert_eq!(session.unsigned_psbt_hash(), Some(unsigned_psbt_hash()));
    }

    #[test]
    fn psbt_created_is_idempotent() {
        let mut session = create_session();
        let _ = session.record_psbt_created(unsigned_psbt_hash()).unwrap();
        assert!(
            session
                .record_psbt_created(unsigned_psbt_hash())
                .unwrap()
                .was_already_applied()
        );
    }

    #[test]
    fn no_signatures_before_psbt_created() {
        let mut session = create_session();
        assert!(matches!(
            add_sig(&mut session, 1),
            Err(PsbtSessionError::NotCollecting(_))
        ));
    }

    #[test]
    fn cannot_attach_psbt_after_cancel() {
        let mut session = create_session();
        let _ = session.cancel("gave up".to_string()).unwrap();
        assert!(matches!(
            session.record_psbt_created(unsigned_psbt_hash()),
            Err(PsbtSessionError::CannotAttachPsbt { .. })
        ));
    }

    #[test]
    fn collects_signatures_up_to_and_beyond_threshold() {
        let mut session = create_collecting_session();
        assert!(add_sig(&mut session, 1).unwrap().did_execute());
        assert!(!session.threshold_met());

        assert!(add_sig(&mut session, 2).unwrap().did_execute());
        assert!(session.threshold_met());
        assert_eq!(session.missing_keystores(), vec![fp(3)]);

        // over-signing before finalize is fine — finalize records sigs_used
        assert!(add_sig(&mut session, 3).unwrap().did_execute());
        assert_eq!(session.signature_count(), 3);
    }

    #[test]
    fn signature_upload_is_idempotent_per_signer() {
        let mut session = create_collecting_session();
        assert!(add_sig(&mut session, 1).unwrap().did_execute());
        assert!(add_sig(&mut session, 1).unwrap().was_already_applied());
        assert_eq!(session.signature_count(), 1);
    }

    #[test]
    fn rejects_unknown_keystore() {
        let mut session = create_collecting_session();
        let result = add_sig(&mut session, 42);
        assert!(matches!(result, Err(PsbtSessionError::UnknownKeystore(_))));
    }

    #[test]
    fn finalize_requires_threshold_and_collected_sigs() {
        let mut session = create_collecting_session();
        let _ = add_sig(&mut session, 1).unwrap();

        // below threshold
        let result = session.finalize(dummy_txid(1), PsbtHash::digest_of(b"final-tx"), vec![fp(1)]);
        assert!(matches!(
            result,
            Err(PsbtSessionError::ThresholdNotMet { .. })
        ));

        // sigs_used must be collected
        let result = session.finalize(
            dummy_txid(1),
            PsbtHash::digest_of(b"final-tx"),
            vec![fp(1), fp(2)],
        );
        assert!(matches!(
            result,
            Err(PsbtSessionError::SigsUsedNotCollected)
        ));
    }

    #[test]
    fn finalize_at_threshold_records_sigs_used() {
        let mut session = create_collecting_session();
        let _ = add_sig(&mut session, 1).unwrap();
        let _ = add_sig(&mut session, 2).unwrap();
        let _ = add_sig(&mut session, 3).unwrap();

        let result = session.finalize(
            dummy_txid(1),
            PsbtHash::digest_of(b"final-tx"),
            vec![fp(2), fp(3)],
        );
        assert!(result.unwrap().did_execute());
        assert_eq!(session.status(), PsbtSessionStatus::Finalized);
        assert_eq!(
            session.finalization().unwrap().sigs_used,
            vec![fp(2), fp(3)]
        );
    }

    #[test]
    fn finalize_is_idempotent() {
        let mut session = create_collecting_session();
        let _ = add_sig(&mut session, 1).unwrap();
        let _ = add_sig(&mut session, 2).unwrap();
        finalize(&mut session, vec![fp(1), fp(2)]);

        let result = session.finalize(
            dummy_txid(1),
            PsbtHash::digest_of(b"final-tx"),
            vec![fp(1), fp(2)],
        );
        assert!(result.unwrap().was_already_applied());
    }

    #[test]
    fn no_signatures_after_finalize_or_cancel() {
        let mut session = create_collecting_session();
        let _ = add_sig(&mut session, 1).unwrap();
        let _ = add_sig(&mut session, 2).unwrap();
        finalize(&mut session, vec![fp(1), fp(2)]);
        assert!(matches!(
            add_sig(&mut session, 3),
            Err(PsbtSessionError::NotCollecting(_))
        ));

        let mut session = create_collecting_session();
        let _ = session.cancel("changed mind".to_string()).unwrap();
        assert!(matches!(
            add_sig(&mut session, 1),
            Err(PsbtSessionError::NotCollecting(_))
        ));
    }

    #[test]
    fn chain_progression_finalize_broadcast_confirm() {
        let mut session = create_collecting_session();
        let _ = add_sig(&mut session, 1).unwrap();
        let _ = add_sig(&mut session, 2).unwrap();
        let txid = dummy_txid(1);
        finalize(&mut session, vec![fp(1), fp(2)]);

        // txid mismatch is rejected — chain events must match the final tx
        assert!(matches!(
            session.mark_broadcast_seen(dummy_txid(9)),
            Err(PsbtSessionError::TxidMismatch)
        ));

        assert!(session.mark_broadcast_seen(txid).unwrap().did_execute());
        assert_eq!(session.status(), PsbtSessionStatus::Broadcast);
        assert!(
            session
                .mark_broadcast_seen(txid)
                .unwrap()
                .was_already_applied()
        );

        assert!(
            session
                .confirm(txid, 800_000, dummy_block_hash(1))
                .unwrap()
                .did_execute()
        );
        assert_eq!(session.status(), PsbtSessionStatus::Confirmed);
    }

    #[test]
    fn broadcast_seen_after_confirm_is_redundant() {
        let mut session = create_collecting_session();
        let _ = add_sig(&mut session, 1).unwrap();
        let _ = add_sig(&mut session, 2).unwrap();
        let txid = dummy_txid(1);
        finalize(&mut session, vec![fp(1), fp(2)]);
        let _ = session.confirm(txid, 800_000, dummy_block_hash(1)).unwrap();

        // catch-up sync delivers the mempool sighting late
        assert!(
            session
                .mark_broadcast_seen(txid)
                .unwrap()
                .was_already_applied()
        );
        assert_eq!(session.status(), PsbtSessionStatus::Confirmed);
    }

    #[test]
    fn reorg_invalidates_and_reconfirm_executes_again() {
        let mut session = create_collecting_session();
        let _ = add_sig(&mut session, 1).unwrap();
        let _ = add_sig(&mut session, 2).unwrap();
        let txid = dummy_txid(1);
        finalize(&mut session, vec![fp(1), fp(2)]);
        let _ = session.mark_broadcast_seen(txid).unwrap();
        let _ = session.confirm(txid, 800_000, dummy_block_hash(1)).unwrap();

        // reorg
        assert!(
            session
                .invalidate(InvalidationReason::Reorged)
                .unwrap()
                .did_execute()
        );
        assert_eq!(session.status(), PsbtSessionStatus::Invalidated);

        // idempotent replay of the same invalidation
        assert!(
            session
                .invalidate(InvalidationReason::Reorged)
                .unwrap()
                .was_already_applied()
        );

        // tx re-confirms in the new best chain — must execute, not be
        // swallowed by the earlier Confirmed event
        assert!(
            session
                .confirm(txid, 800_001, dummy_block_hash(2))
                .unwrap()
                .did_execute()
        );
        assert_eq!(session.status(), PsbtSessionStatus::Confirmed);
    }

    #[test]
    fn cannot_invalidate_before_broadcast() {
        let mut session = create_collecting_session();
        assert!(matches!(
            session.invalidate(InvalidationReason::InputsSpentExternally),
            Err(PsbtSessionError::CannotInvalidate { .. })
        ));
    }

    #[test]
    fn cancel_only_before_broadcast() {
        let mut session = create_session();
        // pending (stuck PSBT creation) can be cancelled
        assert!(
            session
                .cancel("no longer needed".to_string())
                .unwrap()
                .did_execute()
        );
        assert_eq!(session.status(), PsbtSessionStatus::Cancelled);
        assert!(
            session
                .cancel("again".to_string())
                .unwrap()
                .was_already_applied()
        );

        // finalized-but-not-broadcast can still be abandoned
        let mut session = create_collecting_session();
        let _ = add_sig(&mut session, 1).unwrap();
        let _ = add_sig(&mut session, 2).unwrap();
        finalize(&mut session, vec![fp(1), fp(2)]);
        assert!(session.cancel("abandon".to_string()).unwrap().did_execute());

        // once broadcast, the chain decides
        let mut session = create_collecting_session();
        let _ = add_sig(&mut session, 1).unwrap();
        let _ = add_sig(&mut session, 2).unwrap();
        finalize(&mut session, vec![fp(1), fp(2)]);
        let _ = session.mark_broadcast_seen(dummy_txid(1)).unwrap();
        assert!(matches!(
            session.cancel("too late".to_string()),
            Err(PsbtSessionError::CannotCancel { .. })
        ));
    }

    #[test]
    fn proposal_requires_active_wallet() {
        // still collecting keystores: 3 participants, only 1 submitted
        let participants: Vec<UserId> = (0..3).map(|_| UserId::new()).collect();
        let mut wallet = Wallet::try_from_events(
            NewWallet::new(WalletId::new(), Network::Regtest, 2, participants.clone())
                .unwrap()
                .into_events(),
        )
        .unwrap();
        let _ = wallet
            .add_keystore(wallet_keystore(1), participants[0])
            .unwrap();
        assert!(matches!(
            propose(&wallet, sample_spend()),
            Err(PsbtSessionError::WalletNotActive {
                status: WalletStatus::CollectingKeystores,
                ..
            })
        ));

        // cancelled before activation
        let _ = wallet
            .cancel(participants[0], "abandoned".to_string())
            .unwrap();
        assert!(matches!(
            propose(&wallet, sample_spend()),
            Err(PsbtSessionError::WalletNotActive {
                status: WalletStatus::Cancelled,
                ..
            })
        ));
    }

    #[test]
    fn proposal_snapshots_wallet_policy() {
        let wallet = active_wallet(2, &[1, 2, 3]);
        let session =
            PsbtSession::try_from_events(propose(&wallet, sample_spend()).unwrap().into_events())
                .unwrap();
        assert_eq!(session.wallet_id, wallet.id);
        assert_eq!(session.threshold(), 2);
        assert_eq!(session.keystores(), &[fp(1), fp(2), fp(3)]);
    }

    #[test]
    fn duplicate_inputs_rejected() {
        let wallet = active_wallet(2, &[1, 2]);
        let mut spend = sample_spend();
        let dup = spend.inputs[0].clone();
        spend.inputs.push(dup.clone());
        assert!(matches!(
            propose(&wallet, spend),
            Err(PsbtSessionError::DuplicateInput { txid, vout }) if txid == dup.txid && vout == dup.vout
        ));
    }

    #[test]
    fn fee_above_cap_rejected() {
        let wallet = active_wallet(2, &[1, 2]);
        let mut spend = sample_spend();
        spend.fee_sats = MAX_FEE_SATS + 1;
        assert!(matches!(
            propose(&wallet, spend),
            Err(PsbtSessionError::FeeExceedsMax { .. })
        ));
    }

    #[test]
    fn wrong_network_output_address_rejected_at_proposal() {
        // a mainnet destination on a regtest wallet: rejected at proposal,
        // not discovered by the PSBT-creation job after the session exists
        let wallet = active_wallet(2, &[1, 2]);
        let mut spend = sample_spend();
        spend.outputs[0].address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
            .parse()
            .unwrap();
        assert!(matches!(
            propose(&wallet, spend),
            Err(PsbtSessionError::InvalidAddress { .. })
        ));
    }

    #[test]
    fn dust_outputs_rejected() {
        let wallet = active_wallet(2, &[1, 2]);

        // zero- and sub-dust spend outputs
        for amount_sats in [0, 100] {
            let mut spend = sample_spend();
            spend.outputs[0].amount_sats = amount_sats;
            assert!(matches!(
                propose(&wallet, spend),
                Err(PsbtSessionError::DustOutput { .. })
            ));
        }

        // sub-dust change should have been folded into the fee
        let mut spend = sample_spend();
        spend.change_output = Some(ChangeOutput {
            amount_sats: 100,
            derivation_index: 1,
        });
        assert!(matches!(
            propose(&wallet, spend),
            Err(PsbtSessionError::DustOutput { .. })
        ));
    }

    #[test]
    fn empty_spend_rejected() {
        let wallet = active_wallet(2, &[1, 2]);

        let mut spend = sample_spend();
        spend.inputs = vec![];
        assert!(matches!(
            propose(&wallet, spend),
            Err(PsbtSessionError::EmptyInputs)
        ));

        let mut spend = sample_spend();
        spend.outputs = vec![];
        assert!(matches!(
            propose(&wallet, spend),
            Err(PsbtSessionError::EmptyOutputs)
        ));
    }
}
