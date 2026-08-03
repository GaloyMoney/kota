//! The wallet aggregate: a multisig wallet being coordinated.
//!
//! A wallet is *not* born with its descriptor. It is initialized with a
//! policy — an N-of-M threshold over a named set of participants — and
//! each participant then submits their keystore (xpub):
//!
//! ```text
//! Initialized { threshold, participants }
//!     │  KeystoreAdded × participants.len()   (one per participant)
//!     ▼
//! Activated { descriptor, descriptor_fingerprint }
//!
//!     Initialized ──Cancelled──▶ Cancelled   (pre-activation only)
//! ```
//!
//! Only when every participant has submitted does the platform derive
//! the canonical `wsh(sortedmulti(NofM))` descriptor (keystores sorted,
//! so submission order does not affect the result). Until `Activated`
//! the wallet has no address space and no fingerprint — it cannot
//! receive funds and cannot propose spends; `NewPsbtSession::try_new`
//! enforces `status() == WalletStatus::Active`.
//!
//! Participant binding: `Initialized` names the expected participants,
//! and the aggregate enforces one keystore per participant — a
//! non-participant cannot submit, and a participant cannot submit a
//! second key without first removing their previous one
//! (`KeystoreRemoved`, pre-activation only). `submitted_by` /
//! `removed_by` / `cancelled_by` are platform-attributed business
//! facts; *authentication* of the user is the use-case layer's job (the
//! future user crate), the aggregate enforces the structural invariant.
//!
//! Identity is two-layered (see `crate::wallet::descriptor_fingerprint`):
//! `WalletId` is a framework-internal UUID, while
//! `descriptor_fingerprint` is the deterministic content address of
//! (network, canonical descriptor). It exists only from `Activated` on —
//! the DB column is NULL until then, UNIQUE thereafter, so two wallets
//! converging on the same descriptor collide at activation (on update),
//! which the use-case layer turns into an idempotent find.

use derive_builder::Builder;
use serde::{Deserialize, Serialize};

use es_entity::*;

use bitcoin::Network;
use miniscript::descriptor::{Descriptor, DescriptorPublicKey};

use super::primitives::WalletStatus;
use super::{
    WalletError, descriptor_fingerprint, keystore_fingerprint, sortedmulti_wsh_descriptor,
};
use crate::primitives::{DescriptorFingerprint, UserId, WalletId};

#[derive(EsEvent, Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[es_event(id = "WalletId")]
pub enum WalletEvent {
    /// The wallet's policy was registered: an N-of-M multisig on
    /// `network`, expecting one keystore from each of `participants`.
    /// No keys yet — the descriptor cannot be computed until every
    /// participant has submitted.
    Initialized {
        id: WalletId,
        network: Network,
        /// N — signatures required to spend.
        threshold: u32,
        /// M — the participants, each contributing exactly one keystore.
        participants: Vec<UserId>,
    },
    /// A participant's keystore (xpub with origin info, i.e. a Sparrow
    /// `Keystore`) was submitted. Parsed at the boundary, so malformed
    /// keys never enter the event stream.
    KeystoreAdded {
        keystore: DescriptorPublicKey,
        /// Participant who submitted the keystore (platform-attributed).
        submitted_by: UserId,
    },
    /// A participant's previously submitted keystore was withdrawn
    /// (wrong xpub uploaded, device swapped, ...). Only possible before
    /// activation; the participant may then submit a replacement.
    KeystoreRemoved {
        /// Participant whose keystore was removed.
        participant: UserId,
        /// The removed keystore, kept in the event for the audit trail.
        keystore: DescriptorPublicKey,
        /// User who performed the removal (platform-attributed).
        removed_by: UserId,
    },
    /// All participants' keystores collected; the canonical descriptor
    /// was derived and content-addressed. Terminal for the keystore
    /// set — policy changes produce a different descriptor, i.e. a
    /// *different* wallet (see module docs).
    Activated {
        /// Parsed at construction; serde keeps the canonical string
        /// form, so the persisted representation is standard BIP-380.
        descriptor: Descriptor<DescriptorPublicKey>,
        /// Content address of (network, canonical descriptor).
        descriptor_fingerprint: DescriptorFingerprint,
    },
    /// The wallet was abandoned before activation (quorum fell apart,
    /// registered by mistake, ...). Terminal; allows cleanup of a
    /// wallet that would otherwise collect keystores forever.
    Cancelled {
        cancelled_by: UserId,
        reason: String,
    },
}

#[derive(EsEntity, Builder)]
#[builder(pattern = "owned", build_fn(error = "EntityHydrationError"))]
pub struct Wallet {
    pub id: WalletId,
    pub network: Network,
    pub threshold: u32,
    pub participants: Vec<UserId>,
    events: EntityEvents<WalletEvent>,
}

impl Wallet {
    /// Latest lifecycle event wins. `Activated` and `Cancelled` are
    /// both terminal and mutually exclusive (cancellation is rejected
    /// once active), so a plain fold is correct.
    pub fn status(&self) -> WalletStatus {
        self.events
            .iter_all()
            .fold(WalletStatus::default(), |status, event| match event {
                WalletEvent::Activated { .. } => WalletStatus::Active,
                WalletEvent::Cancelled { .. } => WalletStatus::Cancelled,
                _ => status,
            })
    }

    pub fn participants(&self) -> &[UserId] {
        &self.participants
    }

    pub fn total_keystores(&self) -> u32 {
        self.participants.len() as u32
    }

    /// Keystores currently held, paired with the participant who
    /// submitted them, in submission order. Removals are folded out.
    pub fn submissions(&self) -> Vec<(UserId, DescriptorPublicKey)> {
        let mut submissions: Vec<(UserId, DescriptorPublicKey)> = Vec::new();
        for event in self.events.iter_all() {
            match event {
                WalletEvent::KeystoreAdded {
                    keystore,
                    submitted_by,
                } => submissions.push((*submitted_by, keystore.clone())),
                WalletEvent::KeystoreRemoved { participant, .. } => {
                    submissions.retain(|(p, _)| p != participant);
                }
                _ => {}
            }
        }
        submissions
    }

    /// Keystores collected so far, in submission order.
    pub fn keystores(&self) -> Vec<DescriptorPublicKey> {
        self.submissions()
            .into_iter()
            .map(|(_, keystore)| keystore)
            .collect()
    }

    /// Participants who have not (currently) submitted a keystore.
    pub fn pending_participants(&self) -> Vec<UserId> {
        let submitted: Vec<UserId> = self
            .submissions()
            .into_iter()
            .map(|(participant, _)| participant)
            .collect();
        self.participants
            .iter()
            .filter(|p| !submitted.contains(p))
            .copied()
            .collect()
    }

    pub fn missing_keystores(&self) -> u32 {
        self.pending_participants().len() as u32
    }

    /// The canonical descriptor, once all keystores are collected and
    /// the wallet is `Active`.
    pub fn descriptor(&self) -> Option<&Descriptor<DescriptorPublicKey>> {
        self.events.iter_all().find_map(|event| match event {
            WalletEvent::Activated { descriptor, .. } => Some(descriptor),
            _ => None,
        })
    }

    /// Content address of the wallet, once `Active`. NULL in the index
    /// table until then.
    pub fn descriptor_fingerprint(&self) -> Option<DescriptorFingerprint> {
        self.events.iter_all().find_map(|event| match event {
            WalletEvent::Activated {
                descriptor_fingerprint,
                ..
            } => Some(*descriptor_fingerprint),
            _ => None,
        })
    }

    /// Record a participant-submitted keystore.
    ///
    /// One keystore per participant: resubmitting the identical key is
    /// an idempotent no-op (crash/retry) *in any lifecycle state* —
    /// critically including after activation, since the submission that
    /// completes the policy records `Activated` in the same command,
    /// so a retried final submission observes an `Active` wallet and
    /// must still be recognized as already applied. Submitting a
    /// *different* key requires an explicit `remove_keystore` first.
    /// Across participants, master fingerprints (origin fingerprint,
    /// falling back to the key's own) must be distinct — two
    /// participants presenting keys from the same device is a policy
    /// error.
    ///
    /// When this submission completes the policy, the canonical
    /// descriptor is derived (keystores sorted — submission order does
    /// not affect it) and `Activated` is recorded in the same command,
    /// so the wallet becomes active atomically with its final keystore.
    pub fn add_keystore(
        &mut self,
        keystore: DescriptorPublicKey,
        submitted_by: UserId,
    ) -> Result<Idempotent<()>, WalletError> {
        // Idempotency first, before any lifecycle gate: the retry of an
        // already-recorded submission is a no-op even though the wallet
        // may since have activated or been cancelled.
        if let Some((_, existing)) = self
            .submissions()
            .into_iter()
            .find(|(participant, _)| *participant == submitted_by)
            && existing == keystore
        {
            return Ok(Idempotent::AlreadyApplied);
        }
        match self.status() {
            WalletStatus::CollectingKeystores => {}
            WalletStatus::Active => return Err(WalletError::AlreadyActive),
            WalletStatus::Cancelled => return Err(WalletError::Cancelled),
        }
        if !self.participants.contains(&submitted_by) {
            return Err(WalletError::NotAParticipant(submitted_by));
        }
        if self
            .submissions()
            .iter()
            .any(|(participant, _)| *participant == submitted_by)
        {
            // a submission exists and differs from `keystore` (the
            // identical case returned above)
            return Err(WalletError::ParticipantAlreadySubmitted(submitted_by));
        }
        let fingerprint = keystore_fingerprint(&keystore);
        if self
            .keystores()
            .iter()
            .any(|k| keystore_fingerprint(k) == fingerprint)
        {
            return Err(WalletError::DuplicateKeystore(fingerprint));
        }

        // Derive the activation *before* recording anything: if the
        // collected keys cannot form a valid descriptor, the command
        // fails without polluting the event stream.
        let activation = if self.keystores().len() as u32 + 1 == self.total_keystores() {
            let mut keystores = self.keystores();
            keystores.push(keystore.clone());
            let descriptor = sortedmulti_wsh_descriptor(self.threshold as usize, keystores)?;
            let fingerprint = descriptor_fingerprint(&descriptor, self.network);
            Some((descriptor, fingerprint))
        } else {
            None
        };

        self.events.push(WalletEvent::KeystoreAdded {
            keystore,
            submitted_by,
        });
        if let Some((descriptor, fingerprint)) = activation {
            self.events.push(WalletEvent::Activated {
                descriptor,
                descriptor_fingerprint: fingerprint,
            });
        }
        Ok(Idempotent::Executed(()))
    }

    /// Withdraw a participant's keystore (pre-activation only) so they
    /// can submit a replacement — e.g. a wrong xpub uploaded by
    /// mistake. Authorization (the participant themselves, or an
    /// admin) is the use-case layer's job; the aggregate records
    /// `removed_by` for the audit trail.
    ///
    /// Idempotent: removing a participant with no submitted keystore
    /// is a no-op.
    pub fn remove_keystore(
        &mut self,
        participant: UserId,
        removed_by: UserId,
    ) -> Result<Idempotent<()>, WalletError> {
        match self.status() {
            WalletStatus::CollectingKeystores => {}
            WalletStatus::Active => return Err(WalletError::AlreadyActive),
            WalletStatus::Cancelled => return Err(WalletError::Cancelled),
        }
        let Some((_, keystore)) = self
            .submissions()
            .into_iter()
            .find(|(p, _)| *p == participant)
        else {
            return Ok(Idempotent::AlreadyApplied);
        };

        self.events.push(WalletEvent::KeystoreRemoved {
            participant,
            keystore,
            removed_by,
        });
        Ok(Idempotent::Executed(()))
    }

    /// Abandon the wallet before activation — the quorum fell apart or
    /// the wallet was registered by mistake. Cancellation is
    /// pre-activation only: an active wallet has an address space and
    /// possibly funds, so it must be retired, not cancelled (retirement
    /// is future work).
    pub fn cancel(
        &mut self,
        cancelled_by: UserId,
        reason: String,
    ) -> Result<Idempotent<()>, WalletError> {
        idempotency_guard!(
            self.events.iter_all().rev(),
            already_applied: WalletEvent::Cancelled { .. },
        );
        match self.status() {
            WalletStatus::CollectingKeystores => {}
            WalletStatus::Active => return Err(WalletError::CannotCancelActive),
            WalletStatus::Cancelled => unreachable!("idempotency guard returned"),
        }

        self.events.push(WalletEvent::Cancelled {
            cancelled_by,
            reason,
        });
        Ok(Idempotent::Executed(()))
    }
}

impl TryFromEvents<WalletEvent> for Wallet {
    fn try_from_events(events: EntityEvents<WalletEvent>) -> Result<Self, EntityHydrationError> {
        let mut builder = WalletBuilder::default();
        for event in events.iter_all() {
            if let WalletEvent::Initialized {
                id,
                network,
                threshold,
                participants,
            } = event
            {
                builder = builder
                    .id(*id)
                    .network(*network)
                    .threshold(*threshold)
                    .participants(participants.clone());
            }
        }
        builder.events(events).build()
    }
}

#[derive(Debug, Builder)]
pub struct NewWallet {
    #[builder(setter(into))]
    pub(super) id: WalletId,
    network: Network,
    threshold: u32,
    participants: Vec<UserId>,
}

impl NewWallet {
    pub fn builder() -> NewWalletBuilder {
        NewWalletBuilder::default()
    }

    /// Register a wallet policy: an N-of-M multisig on `network`,
    /// expecting one keystore from each participant.
    ///
    /// Only the policy is validated here (participants non-empty and
    /// distinct, 0 < N <= M); keystore collection and descriptor
    /// derivation happen on the aggregate.
    pub fn new(
        id: WalletId,
        network: Network,
        threshold: u32,
        participants: Vec<UserId>,
    ) -> Result<Self, WalletError> {
        if participants.is_empty() || threshold == 0 || threshold as usize > participants.len() {
            return Err(WalletError::InvalidPolicy {
                threshold,
                total_keystores: participants.len() as u32,
            });
        }
        for (i, participant) in participants.iter().enumerate() {
            if participants[..i].contains(participant) {
                return Err(WalletError::DuplicateParticipant(*participant));
            }
        }
        Ok(Self {
            id,
            network,
            threshold,
            participants,
        })
    }

    pub(super) fn status(&self) -> WalletStatus {
        WalletStatus::CollectingKeystores
    }

    pub(super) fn descriptor_fingerprint(&self) -> Option<DescriptorFingerprint> {
        None
    }
}

impl IntoEvents<WalletEvent> for NewWallet {
    fn into_events(self) -> EntityEvents<WalletEvent> {
        EntityEvents::init(
            self.id,
            [WalletEvent::Initialized {
                id: self.id,
                network: self.network,
                threshold: self.threshold,
                participants: self.participants,
            }],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::tests::{different_keystore_same_fingerprint, keystore};

    const NETWORK: Network = Network::Regtest;

    fn participants() -> Vec<UserId> {
        (0..3).map(|_| UserId::new()).collect()
    }

    fn new_wallet() -> (Wallet, Vec<UserId>) {
        let participants = participants();
        let wallet = Wallet::try_from_events(
            NewWallet::new(WalletId::new(), NETWORK, 2, participants.clone())
                .unwrap()
                .into_events(),
        )
        .unwrap();
        (wallet, participants)
    }

    fn active_wallet() -> (Wallet, Vec<UserId>) {
        let (mut wallet, participants) = new_wallet();
        for (i, seed) in [1, 2, 3].iter().enumerate() {
            let _ = wallet
                .add_keystore(keystore(*seed), participants[i])
                .unwrap();
        }
        (wallet, participants)
    }

    #[test]
    fn starts_collecting_with_no_descriptor() {
        let (wallet, participants) = new_wallet();
        assert_eq!(wallet.status(), WalletStatus::CollectingKeystores);
        assert_eq!(wallet.descriptor(), None);
        assert_eq!(wallet.descriptor_fingerprint(), None);
        assert_eq!(wallet.missing_keystores(), 3);
        assert_eq!(wallet.pending_participants(), participants);
    }

    #[test]
    fn activates_atomically_with_final_keystore() {
        let (mut wallet, participants) = new_wallet();

        let _ = wallet.add_keystore(keystore(1), participants[0]).unwrap();
        let _ = wallet.add_keystore(keystore(2), participants[1]).unwrap();
        assert_eq!(wallet.status(), WalletStatus::CollectingKeystores);
        assert_eq!(wallet.missing_keystores(), 1);
        assert_eq!(wallet.pending_participants(), vec![participants[2]]);

        let _ = wallet.add_keystore(keystore(3), participants[2]).unwrap();
        assert_eq!(wallet.status(), WalletStatus::Active);
        assert_eq!(wallet.missing_keystores(), 0);

        let expected =
            sortedmulti_wsh_descriptor(2, vec![keystore(1), keystore(2), keystore(3)]).unwrap();
        assert_eq!(wallet.descriptor(), Some(&expected));
        assert_eq!(
            wallet.descriptor_fingerprint(),
            Some(descriptor_fingerprint(&expected, NETWORK))
        );
    }

    #[test]
    fn activation_is_submission_order_independent() {
        let (mut forward, participants) = new_wallet();
        for (i, seed) in [1, 2, 3].iter().enumerate() {
            let _ = forward
                .add_keystore(keystore(*seed), participants[i])
                .unwrap();
        }
        let (mut reverse, participants) = new_wallet();
        for (i, seed) in [3, 2, 1].iter().enumerate() {
            let _ = reverse
                .add_keystore(keystore(*seed), participants[i])
                .unwrap();
        }
        assert_eq!(
            forward.descriptor_fingerprint(),
            reverse.descriptor_fingerprint()
        );
        assert_eq!(forward.descriptor(), reverse.descriptor());
    }

    #[test]
    fn non_participant_cannot_submit() {
        let (mut wallet, _) = new_wallet();
        assert!(matches!(
            wallet.add_keystore(keystore(1), UserId::new()),
            Err(WalletError::NotAParticipant(_))
        ));
        assert_eq!(wallet.keystores().len(), 0);
    }

    #[test]
    fn resubmitting_identical_keystore_is_idempotent() {
        let (mut wallet, participants) = new_wallet();
        assert!(
            wallet
                .add_keystore(keystore(1), participants[0])
                .unwrap()
                .did_execute()
        );
        assert!(
            wallet
                .add_keystore(keystore(1), participants[0])
                .unwrap()
                .was_already_applied()
        );
        assert_eq!(wallet.keystores().len(), 1);
    }

    #[test]
    fn activating_submission_is_retryable() {
        let (mut wallet, participants) = new_wallet();
        let _ = wallet.add_keystore(keystore(1), participants[0]).unwrap();
        let _ = wallet.add_keystore(keystore(2), participants[1]).unwrap();
        assert!(
            wallet
                .add_keystore(keystore(3), participants[2])
                .unwrap()
                .did_execute()
        );
        assert_eq!(wallet.status(), WalletStatus::Active);

        // crash/retry of the submission that activated the wallet: the
        // wallet is now Active, but the retry must still be recognized
        // as already applied, not rejected as AlreadyActive
        assert!(
            wallet
                .add_keystore(keystore(3), participants[2])
                .unwrap()
                .was_already_applied()
        );
        assert_eq!(wallet.keystores().len(), 3);
    }

    #[test]
    fn submission_retry_after_cancel_is_still_idempotent() {
        let (mut wallet, participants) = new_wallet();
        let _ = wallet.add_keystore(keystore(1), participants[0]).unwrap();
        let _ = wallet
            .cancel(participants[0], "abandoned".to_string())
            .unwrap();

        // a retry in flight from before the cancellation lands as a
        // no-op, not an error
        assert!(
            wallet
                .add_keystore(keystore(1), participants[0])
                .unwrap()
                .was_already_applied()
        );
    }

    #[test]
    fn participant_cannot_submit_second_key_without_removal() {
        let (mut wallet, participants) = new_wallet();
        let _ = wallet.add_keystore(keystore(1), participants[0]).unwrap();
        assert!(matches!(
            wallet.add_keystore(keystore(9), participants[0]),
            Err(WalletError::ParticipantAlreadySubmitted(_))
        ));
        assert_eq!(wallet.keystores(), vec![keystore(1)]);
    }

    #[test]
    fn different_key_with_registered_fingerprint_is_rejected() {
        let (mut wallet, participants) = new_wallet();
        let _ = wallet.add_keystore(keystore(1), participants[0]).unwrap();
        // a *second participant* presenting a key from the same device
        let result = wallet.add_keystore(different_keystore_same_fingerprint(1), participants[1]);
        assert!(matches!(result, Err(WalletError::DuplicateKeystore(_))));
        assert_eq!(wallet.keystores().len(), 1);
    }

    #[test]
    fn removed_keystore_can_be_replaced() {
        let (mut wallet, participants) = new_wallet();
        let _ = wallet.add_keystore(keystore(1), participants[0]).unwrap();

        assert!(
            wallet
                .remove_keystore(participants[0], participants[0])
                .unwrap()
                .did_execute()
        );
        assert_eq!(wallet.keystores().len(), 0);
        assert_eq!(wallet.pending_participants().len(), 3);

        // the participant can now submit the replacement
        assert!(
            wallet
                .add_keystore(keystore(9), participants[0])
                .unwrap()
                .did_execute()
        );
        assert_eq!(wallet.keystores(), vec![keystore(9)]);
    }

    #[test]
    fn removing_without_submission_is_idempotent() {
        let (mut wallet, participants) = new_wallet();
        assert!(
            wallet
                .remove_keystore(participants[0], participants[1])
                .unwrap()
                .was_already_applied()
        );
    }

    #[test]
    fn keystores_are_immutable_after_activation() {
        let (mut wallet, participants) = active_wallet();
        assert!(matches!(
            wallet.add_keystore(keystore(4), participants[0]),
            Err(WalletError::AlreadyActive)
        ));
        assert!(matches!(
            wallet.remove_keystore(participants[0], participants[0]),
            Err(WalletError::AlreadyActive)
        ));
    }

    #[test]
    fn cancel_abandons_keystore_collection() {
        let (mut wallet, participants) = new_wallet();
        let _ = wallet.add_keystore(keystore(1), participants[0]).unwrap();

        assert!(
            wallet
                .cancel(participants[0], "quorum fell apart".to_string())
                .unwrap()
                .did_execute()
        );
        assert_eq!(wallet.status(), WalletStatus::Cancelled);
        assert!(
            wallet
                .cancel(participants[0], "again".to_string())
                .unwrap()
                .was_already_applied()
        );

        // a cancelled wallet accepts no further keystores
        assert!(matches!(
            wallet.add_keystore(keystore(2), participants[1]),
            Err(WalletError::Cancelled)
        ));
        assert!(matches!(
            wallet.remove_keystore(participants[0], participants[0]),
            Err(WalletError::Cancelled)
        ));
    }

    #[test]
    fn active_wallet_cannot_be_cancelled() {
        let (mut wallet, participants) = active_wallet();
        assert!(matches!(
            wallet.cancel(participants[0], "too late".to_string()),
            Err(WalletError::CannotCancelActive)
        ));
        assert_eq!(wallet.status(), WalletStatus::Active);
    }

    #[test]
    fn invalid_policies_are_rejected() {
        let participants = participants();
        assert!(matches!(
            NewWallet::new(WalletId::new(), NETWORK, 0, participants.clone()),
            Err(WalletError::InvalidPolicy { .. })
        ));
        assert!(matches!(
            NewWallet::new(WalletId::new(), NETWORK, 4, participants.clone()),
            Err(WalletError::InvalidPolicy { .. })
        ));
        assert!(matches!(
            NewWallet::new(WalletId::new(), NETWORK, 1, vec![]),
            Err(WalletError::InvalidPolicy { .. })
        ));
        assert!(matches!(
            NewWallet::new(
                WalletId::new(),
                NETWORK,
                2,
                vec![participants[0], participants[1], participants[0]],
            ),
            Err(WalletError::DuplicateParticipant(_))
        ));
        assert!(NewWallet::new(WalletId::new(), NETWORK, 3, participants.clone()).is_ok());
        assert!(NewWallet::new(WalletId::new(), NETWORK, 1, vec![participants[0]]).is_ok());
    }

    #[test]
    fn hydration_rebuilds_full_state() {
        let (mut wallet, participants) = new_wallet();
        let _ = wallet.add_keystore(keystore(1), participants[0]).unwrap();
        let _ = wallet
            .remove_keystore(participants[0], participants[0])
            .unwrap();
        let _ = wallet.add_keystore(keystore(9), participants[0]).unwrap();
        let _ = wallet.add_keystore(keystore(2), participants[1]).unwrap();
        let _ = wallet.add_keystore(keystore(3), participants[2]).unwrap();

        let hydrated = Wallet::try_from_events(wallet.events.clone()).unwrap();
        assert_eq!(hydrated.status(), WalletStatus::Active);
        assert_eq!(hydrated.descriptor(), wallet.descriptor());
        assert_eq!(hydrated.keystores(), wallet.keystores());
        assert_eq!(hydrated.submissions(), wallet.submissions());
        assert_eq!(hydrated.network, NETWORK);
        assert_eq!(hydrated.threshold, 2);
        assert_eq!(hydrated.participants, participants);
    }
}
