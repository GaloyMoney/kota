use thiserror::Error;

use bitcoin::bip32::Fingerprint as KeyFingerprint;

use super::primitives::PsbtSessionStatus;
use super::repo::{
    PsbtSessionCreateError, PsbtSessionFindError, PsbtSessionModifyError, PsbtSessionQueryError,
};
use crate::primitives::PsbtSessionId;

#[derive(Error, Debug)]
pub enum PsbtSessionError {
    #[error("PsbtSessionError - Sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("PsbtSessionError - Create: {0}")]
    Create(#[from] PsbtSessionCreateError),
    #[error("PsbtSessionError - Modify: {0}")]
    Modify(#[from] PsbtSessionModifyError),
    #[error("PsbtSessionError - Find: {0}")]
    Find(#[from] PsbtSessionFindError),
    #[error("PsbtSessionError - Query: {0}")]
    Query(#[from] PsbtSessionQueryError),
    #[error("PsbtSessionError - InvalidPolicy: threshold {threshold} with {keystores} keystores")]
    InvalidPolicy { threshold: u32, keystores: usize },
    #[error("PsbtSessionError - DuplicateKeystore")]
    DuplicateKeystore,
    #[error("PsbtSessionError - NotCollecting: session {0} is not collecting signatures")]
    NotCollecting(PsbtSessionId),
    #[error("PsbtSessionError - UnknownKeystore: {0} is not part of this wallet's policy")]
    UnknownKeystore(KeyFingerprint),
    #[error("PsbtSessionError - EmptyInputs: a spend must consume at least one utxo")]
    EmptyInputs,
    #[error("PsbtSessionError - EmptyOutputs: a spend must have at least one output")]
    EmptyOutputs,
    #[error("PsbtSessionError - CannotAttachPsbt: session {id} is in status {status}")]
    CannotAttachPsbt {
        id: PsbtSessionId,
        status: PsbtSessionStatus,
    },
    #[error(
        "PsbtSessionError - ThresholdNotMet: {collected} of {threshold} required signatures provided"
    )]
    ThresholdNotMet { collected: usize, threshold: u32 },
    #[error(
        "PsbtSessionError - SigsUsedNotCollected: sigs_used must be a subset of collected signatures"
    )]
    SigsUsedNotCollected,
    #[error("PsbtSessionError - DuplicateSigsUsed")]
    DuplicateSigsUsed,
    #[error("PsbtSessionError - NotFinalized: session {0} has no final transaction")]
    NotFinalized(PsbtSessionId),
    #[error("PsbtSessionError - TxidMismatch: observed txid does not match finalized txid")]
    TxidMismatch,
    #[error("PsbtSessionError - NotYetExpired: session expires at {expires_at}")]
    NotYetExpired {
        expires_at: chrono::DateTime<chrono::Utc>,
    },
    #[error("PsbtSessionError - CannotCancel: session {id} is in status {status}")]
    CannotCancel {
        id: PsbtSessionId,
        status: PsbtSessionStatus,
    },
    #[error("PsbtSessionError - CannotExpire: session {id} is in status {status}")]
    CannotExpire {
        id: PsbtSessionId,
        status: PsbtSessionStatus,
    },
    #[error("PsbtSessionError - CannotInvalidate: session {id} is in status {status}")]
    CannotInvalidate {
        id: PsbtSessionId,
        status: PsbtSessionStatus,
    },
}
