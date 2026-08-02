use bitcoin::{Txid, bip32::Fingerprint as KeyFingerprint};
use serde::{Deserialize, Serialize};
use strum::{AsRefStr, Display, EnumString};

use crate::primitives::PsbtHash;

/// Lifecycle status, derived by folding the event stream.
///
/// Note the two causality streams feeding this machine:
/// - user commands: Proposed/SignatureAdded/Finalized/Cancelled
/// - chain sync (via outbox consumer): BroadcastSeen/Confirmed/Invalidated
///
/// Chain-observed states are reversible (reorgs), so "latest lifecycle
/// event wins" when folding — `Confirmed` can be followed by `Invalidated`
/// and then by a new `Confirmed`.
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    AsRefStr,
    Display,
    EnumString,
)]
#[strum(serialize_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum PsbtSessionStatus {
    #[default]
    Collecting,
    Finalized,
    Broadcast,
    Confirmed,
    Invalidated,
    Expired,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvalidationReason {
    /// A reorg unwound a previously observed confirmation.
    Reorged,
    /// One or more inputs were spent by a different transaction
    /// (competing proposal, external sweep). The PSBT can never confirm.
    InputsSpentExternally,
    /// A fee-bumped replacement of this proposal was broadcast instead.
    ReplacedByFeeBump,
    /// Dropped from the mempool (e.g. fee below minimum after eviction).
    MempoolEvicted,
}

/// A collected signature: who signed, and where the signed PSBT blob lives.
///
/// Collected is not the same as *used*: more signatures than the threshold
/// may be collected (concurrent uploads); `FinalizationRecord::sigs_used`
/// records exactly which signatures ended up in the final transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureRecord {
    pub fingerprint: KeyFingerprint,
    pub signed_psbt_hash: PsbtHash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FinalizationRecord {
    pub txid: Txid,
    pub final_tx_hash: PsbtHash,
    pub sigs_used: Vec<KeyFingerprint>,
}
