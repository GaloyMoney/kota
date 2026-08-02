use derive_builder::Builder;
use serde::{Deserialize, Serialize};

use es_entity::*;

use bitcoin::{BlockHash, Txid, bip32::Fingerprint as KeyFingerprint};
use chrono::{DateTime, Utc};

use crate::primitives::{PsbtHash, PsbtSessionId, UserId, WalletId};

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
        expires_at: DateTime<Utc>,
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
    Expired {},
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
    expires_at: DateTime<Utc>,
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
                PsbtSessionEvent::Expired { .. } => return PsbtSessionStatus::Expired,
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

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
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
    /// against the blob at `signed_psbt_hash` before calling this; the entity
    /// only enforces policy membership and lifecycle state. That validation
    /// also enforces completeness (every input signed) — the first upload per
    /// fingerprint is final, so a partially-signed PSBT must never be
    /// accepted.
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

    /// PSBTs don't expire on-chain; expiry is a platform-level policy to
    /// bound how long a proposal can collect signatures (fee market drift,
    /// UTXO availability).
    pub fn expire(&mut self, now: DateTime<Utc>) -> Result<Idempotent<()>, PsbtSessionError> {
        idempotency_guard!(
            self.events.iter_all().rev(),
            already_applied: PsbtSessionEvent::Expired { .. },
        );
        match self.status() {
            PsbtSessionStatus::Pending | PsbtSessionStatus::Collecting => {}
            status => {
                return Err(PsbtSessionError::CannotExpire {
                    id: self.id,
                    status,
                });
            }
        }
        if now < self.expires_at {
            return Err(PsbtSessionError::NotYetExpired {
                expires_at: self.expires_at,
            });
        }

        self.events.push(PsbtSessionEvent::Expired {});
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
                    expires_at,
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
                        .keystores(keystores.clone())
                        .expires_at(*expires_at);
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
                | PsbtSessionEvent::Expired { .. }
                | PsbtSessionEvent::Cancelled { .. } => {}
            }
        }
        builder.signatures(signatures).events(events).build()
    }
}

/// Signing policy of the wallet, snapshotted at session creation (Sparrow
/// vocabulary: N-of-M `threshold` over the wallet's `keystores`). The
/// snapshot pins the policy even if wallet membership changes later.
#[derive(Debug, Clone)]
pub struct Policy {
    pub threshold: u32,
    pub keystores: Vec<KeyFingerprint>,
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
    expires_at: DateTime<Utc>,
}

impl NewPsbtSession {
    pub fn builder() -> NewPsbtSessionBuilder {
        NewPsbtSessionBuilder::default()
    }

    pub fn try_new(
        id: PsbtSessionId,
        wallet_id: WalletId,
        proposed_by: UserId,
        spend: SpendSpec,
        policy: Policy,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, PsbtSessionError> {
        let SpendSpec {
            inputs,
            outputs,
            fee_sats,
            change_output,
        } = spend;
        if inputs.is_empty() {
            return Err(PsbtSessionError::EmptyInputs);
        }
        if outputs.is_empty() {
            return Err(PsbtSessionError::EmptyOutputs);
        }
        let Policy {
            threshold,
            keystores,
        } = policy;
        if threshold == 0 || threshold as usize > keystores.len() {
            return Err(PsbtSessionError::InvalidPolicy {
                threshold,
                keystores: keystores.len(),
            });
        }
        {
            let mut dedup = keystores.clone();
            dedup.sort();
            dedup.dedup();
            if dedup.len() != keystores.len() {
                return Err(PsbtSessionError::DuplicateKeystore);
            }
        }

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
            expires_at,
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
                expires_at: self.expires_at,
            }],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;

    fn fp(byte: u8) -> KeyFingerprint {
        KeyFingerprint::from([byte, byte, byte, byte])
    }

    fn dummy_txid(byte: u8) -> Txid {
        Txid::from_byte_array([byte; 32])
    }

    fn dummy_block_hash(byte: u8) -> BlockHash {
        BlockHash::from_byte_array([byte; 32])
    }

    fn expires_at() -> DateTime<Utc> {
        DateTime::from_timestamp(2_000_000_000, 0).unwrap()
    }

    fn sample_spend() -> SpendSpec {
        SpendSpec {
            inputs: vec![OutPointRef {
                txid: dummy_txid(100),
                vout: 0,
            }],
            outputs: vec![SpendOutput {
                address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
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

    fn new_session(threshold: u32, signers: Vec<KeyFingerprint>) -> NewPsbtSession {
        NewPsbtSession::try_new(
            PsbtSessionId::new(),
            WalletId::new(),
            UserId::new(),
            sample_spend(),
            Policy {
                threshold,
                keystores: signers,
            },
            expires_at(),
        )
        .unwrap()
    }

    /// A freshly proposed session: Pending, no PSBT yet.
    fn create_session() -> PsbtSession {
        let signers = vec![fp(1), fp(2), fp(3)];
        PsbtSession::try_from_events(new_session(2, signers).into_events()).unwrap()
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
    fn expiry_is_platform_policy() {
        let mut session = create_collecting_session();

        let before_expiry = expires_at() - chrono::Duration::hours(1);
        assert!(matches!(
            session.expire(before_expiry),
            Err(PsbtSessionError::NotYetExpired { .. })
        ));

        assert!(session.expire(expires_at()).unwrap().did_execute());
        assert_eq!(session.status(), PsbtSessionStatus::Expired);
        assert!(session.expire(expires_at()).unwrap().was_already_applied());
    }

    #[test]
    fn pending_session_can_expire_too() {
        let mut session = create_session();
        assert!(session.expire(expires_at()).unwrap().did_execute());
        assert_eq!(session.status(), PsbtSessionStatus::Expired);
    }

    #[test]
    fn cannot_expire_finalized_session() {
        let mut session = create_collecting_session();
        let _ = add_sig(&mut session, 1).unwrap();
        let _ = add_sig(&mut session, 2).unwrap();
        finalize(&mut session, vec![fp(1), fp(2)]);
        assert!(matches!(
            session.expire(expires_at()),
            Err(PsbtSessionError::CannotExpire { .. })
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
    fn invalid_policies_rejected() {
        let signers = vec![fp(1), fp(2)];
        let policy = |threshold, keystores| Policy {
            threshold,
            keystores,
        };
        assert!(matches!(
            NewPsbtSession::try_new(
                PsbtSessionId::new(),
                WalletId::new(),
                UserId::new(),
                sample_spend(),
                policy(0, signers.clone()),
                expires_at(),
            ),
            Err(PsbtSessionError::InvalidPolicy { .. })
        ));
        assert!(matches!(
            NewPsbtSession::try_new(
                PsbtSessionId::new(),
                WalletId::new(),
                UserId::new(),
                sample_spend(),
                policy(3, signers),
                expires_at(),
            ),
            Err(PsbtSessionError::InvalidPolicy { .. })
        ));
        assert!(matches!(
            NewPsbtSession::try_new(
                PsbtSessionId::new(),
                WalletId::new(),
                UserId::new(),
                sample_spend(),
                policy(1, vec![fp(1), fp(1)]),
                expires_at(),
            ),
            Err(PsbtSessionError::DuplicateKeystore)
        ));
    }

    #[test]
    fn empty_spend_rejected() {
        let signers = vec![fp(1), fp(2)];
        let policy = Policy {
            threshold: 2,
            keystores: signers,
        };

        let mut spend = sample_spend();
        spend.inputs = vec![];
        assert!(matches!(
            NewPsbtSession::try_new(
                PsbtSessionId::new(),
                WalletId::new(),
                UserId::new(),
                spend,
                policy.clone(),
                expires_at(),
            ),
            Err(PsbtSessionError::EmptyInputs)
        ));

        let mut spend = sample_spend();
        spend.outputs = vec![];
        assert!(matches!(
            NewPsbtSession::try_new(
                PsbtSessionId::new(),
                WalletId::new(),
                UserId::new(),
                spend,
                policy,
                expires_at(),
            ),
            Err(PsbtSessionError::EmptyOutputs)
        ));
    }
}
