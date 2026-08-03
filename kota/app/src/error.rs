use thiserror::Error;

use core_coordination::primitives::{PsbtSessionId, UserId, WalletId};
use core_coordination::psbt::PsbtValidationError;
use core_coordination::psbt_session::PsbtSessionError;
use core_coordination::psbt_session::repo::{
    PsbtSessionCreateError, PsbtSessionFindError, PsbtSessionModifyError, PsbtSessionQueryError,
};
use core_coordination::storage::BlobFetchError;
use core_coordination::wallet::WalletError;
use core_coordination::wallet::repo::{
    WalletCreateError, WalletFindError, WalletModifyError, WalletQueryError,
};

#[derive(Error, Debug)]
pub enum CoordinationError {
    #[error("CoordinationError - Sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("CoordinationError - Job: {0}")]
    Job(#[from] job::error::JobError),
    #[error("CoordinationError - Wallet: {0}")]
    Wallet(#[from] WalletError),
    #[error("CoordinationError - PsbtSession: {0}")]
    PsbtSession(#[from] PsbtSessionError),
    #[error("CoordinationError - PsbtValidation: {0}")]
    PsbtValidation(#[from] PsbtValidationError),
    #[error("CoordinationError - WalletCreate: {0}")]
    WalletCreate(#[from] WalletCreateError),
    #[error("CoordinationError - WalletFind: {0}")]
    WalletFind(#[from] WalletFindError),
    #[error("CoordinationError - WalletModify: {0}")]
    WalletModify(#[from] WalletModifyError),
    #[error("CoordinationError - SessionCreate: {0}")]
    SessionCreate(#[from] PsbtSessionCreateError),
    #[error("CoordinationError - SessionFind: {0}")]
    SessionFind(#[from] PsbtSessionFindError),
    #[error("CoordinationError - SessionModify: {0}")]
    SessionModify(#[from] PsbtSessionModifyError),
    #[error("CoordinationError - WalletQuery: {0}")]
    WalletQuery(#[from] WalletQueryError),
    #[error("CoordinationError - SessionQuery: {0}")]
    SessionQuery(#[from] PsbtSessionQueryError),
    #[error(
        "CoordinationError - SignerNotBound: user {user_id} has no keystore in wallet {wallet_id}"
    )]
    SignerNotBound {
        wallet_id: WalletId,
        user_id: UserId,
    },
    #[error(
        "CoordinationError - UnsignedPsbtNotReady: session {0} has no unsigned PSBT yet \
         (the creation job has not run)"
    )]
    UnsignedPsbtNotReady(PsbtSessionId),
    #[error("CoordinationError - BlobFetch: {0}")]
    BlobFetch(#[from] BlobFetchError),
}
