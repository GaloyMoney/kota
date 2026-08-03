use async_graphql::*;

use kota_app::CoordinationError;

use crate::app_and_sub_from_ctx;
use crate::primitives::*;

pub use core_coordination::psbt_session::PsbtSession as DomainPsbtSession;
use core_coordination::psbt_session::{
    ChangeOutput as DomainChangeOutput, OutPointRef, PsbtSessionStatus as DomainPsbtSessionStatus,
    SpendOutput as DomainSpendOutput, SpendSpec,
};

#[derive(Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsbtSessionStatus {
    Pending,
    Collecting,
    Finalized,
    Broadcast,
    Confirmed,
    Invalidated,
    Cancelled,
}

impl From<DomainPsbtSessionStatus> for PsbtSessionStatus {
    fn from(status: DomainPsbtSessionStatus) -> Self {
        match status {
            DomainPsbtSessionStatus::Pending => Self::Pending,
            DomainPsbtSessionStatus::Collecting => Self::Collecting,
            DomainPsbtSessionStatus::Finalized => Self::Finalized,
            DomainPsbtSessionStatus::Broadcast => Self::Broadcast,
            DomainPsbtSessionStatus::Confirmed => Self::Confirmed,
            DomainPsbtSessionStatus::Invalidated => Self::Invalidated,
            DomainPsbtSessionStatus::Cancelled => Self::Cancelled,
        }
    }
}

#[derive(SimpleObject, Clone)]
pub struct SpendOutPoint {
    txid: String,
    vout: u32,
}

impl From<&OutPointRef> for SpendOutPoint {
    fn from(outpoint: &OutPointRef) -> Self {
        Self {
            txid: outpoint.txid.to_string(),
            vout: outpoint.vout,
        }
    }
}

#[derive(SimpleObject, Clone)]
pub struct SpendOutput {
    address: String,
    amount_sats: u64,
}

impl From<&DomainSpendOutput> for SpendOutput {
    fn from(output: &DomainSpendOutput) -> Self {
        Self {
            // Display is only implemented for network-checked
            // addresses; the string form is identical either way.
            address: output
                .address
                .as_unchecked()
                .clone()
                .assume_checked()
                .to_string(),
            amount_sats: output.amount_sats,
        }
    }
}

#[derive(SimpleObject, Clone)]
pub struct ChangeOutput {
    amount_sats: u64,
    /// Derivation index on the wallet descriptor the platform derives
    /// the change address from — never client-supplied.
    derivation_index: u32,
}

impl From<&DomainChangeOutput> for ChangeOutput {
    fn from(change: &DomainChangeOutput) -> Self {
        Self {
            amount_sats: change.amount_sats,
            derivation_index: change.derivation_index,
        }
    }
}

/// A collected signature: the signer's master fingerprint and the
/// content address of the platform-built merged PSBT blob.
#[derive(SimpleObject, Clone)]
pub struct CollectedSignature {
    fingerprint: String,
    signed_psbt_hash: String,
}

/// Once finalized: the txid, the content address of the final
/// transaction blob, and exactly which signatures were used.
#[derive(SimpleObject, Clone)]
pub struct Finalization {
    txid: String,
    final_tx_hash: String,
    sigs_used: Vec<String>,
}

#[derive(SimpleObject, Clone)]
#[graphql(complex)]
pub struct PsbtSession {
    psbt_session_id: PsbtSessionId,
    wallet_id: WalletId,
    proposed_by: UserId,
    status: PsbtSessionStatus,
    threshold: u32,
    signature_count: u32,
    threshold_met: bool,
    /// Content address of the unsigned PSBT blob, once the creation
    /// job has run (`Collecting` onwards).
    unsigned_psbt_hash: Option<String>,
    #[graphql(skip)]
    pub(super) entity: Arc<DomainPsbtSession>,
}

impl From<DomainPsbtSession> for PsbtSession {
    fn from(session: DomainPsbtSession) -> Self {
        Self {
            psbt_session_id: session.id,
            wallet_id: session.wallet_id,
            proposed_by: session.proposed_by,
            status: session.status().into(),
            threshold: session.threshold(),
            signature_count: session.signature_count() as u32,
            threshold_met: session.threshold_met(),
            unsigned_psbt_hash: session.unsigned_psbt_hash().map(|h| h.to_string()),
            entity: Arc::new(session),
        }
    }
}

#[ComplexObject]
impl PsbtSession {
    async fn inputs(&self) -> Vec<SpendOutPoint> {
        self.entity.inputs.iter().map(SpendOutPoint::from).collect()
    }

    async fn outputs(&self) -> Vec<SpendOutput> {
        self.entity.outputs.iter().map(SpendOutput::from).collect()
    }

    async fn fee_sats(&self) -> u64 {
        self.entity.fee_sats
    }

    async fn change_output(&self) -> Option<ChangeOutput> {
        self.entity.change_output.as_ref().map(ChangeOutput::from)
    }

    async fn signatures(&self) -> Vec<CollectedSignature> {
        self.entity
            .signatures()
            .iter()
            .map(|record| CollectedSignature {
                fingerprint: record.fingerprint.to_string(),
                signed_psbt_hash: record.signed_psbt_hash.to_string(),
            })
            .collect()
    }

    /// Master fingerprints that have not yet signed.
    async fn missing_keystores(&self) -> Vec<String> {
        self.entity
            .missing_keystores()
            .iter()
            .map(|f| f.to_string())
            .collect()
    }

    async fn finalization(&self) -> Option<Finalization> {
        self.entity.finalization().map(|f| Finalization {
            txid: f.txid.to_string(),
            final_tx_hash: f.final_tx_hash.to_string(),
            sigs_used: f.sigs_used.iter().map(|fp| fp.to_string()).collect(),
        })
    }

    /// The unsigned PSBT bytes (base64) a signer downloads to their
    /// device. `null` until the creation job has run.
    async fn unsigned_psbt(&self, ctx: &Context<'_>) -> async_graphql::Result<Option<Base64>> {
        let (app, _) = app_and_sub_from_ctx!(ctx);
        match app.unsigned_psbt(self.entity.id).await {
            Ok(bytes) => Ok(Some(bytes.into())),
            Err(CoordinationError::UnsignedPsbtNotReady(_)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

#[derive(InputObject)]
pub struct SpendOutPointInput {
    pub txid: String,
    pub vout: u32,
}

#[derive(InputObject)]
pub struct SpendOutputInput {
    pub address: String,
    pub amount_sats: u64,
}

#[derive(InputObject)]
pub struct ChangeOutputInput {
    pub amount_sats: u64,
    pub derivation_index: u32,
}

#[derive(InputObject)]
pub struct SpendProposeInput {
    pub wallet_id: WalletId,
    pub inputs: Vec<SpendOutPointInput>,
    pub outputs: Vec<SpendOutputInput>,
    pub fee_sats: u64,
    pub change_output: Option<ChangeOutputInput>,
}

impl SpendProposeInput {
    /// Parse the stringly boundary types (txids, addresses) into the
    /// domain `SpendSpec`.
    pub fn into_wallet_and_spec(self) -> async_graphql::Result<(WalletId, SpendSpec)> {
        let inputs =
            self.inputs
                .iter()
                .map(|input| {
                    Ok(OutPointRef {
                        txid: input.txid.parse().map_err(|e| {
                            Error::new(format!("invalid txid '{}': {e}", input.txid))
                        })?,
                        vout: input.vout,
                    })
                })
                .collect::<async_graphql::Result<Vec<_>>>()?;
        let outputs = self
            .outputs
            .iter()
            .map(|input| {
                Ok(DomainSpendOutput {
                    address: input.address.parse().map_err(|e| {
                        Error::new(format!("invalid address '{}': {e}", input.address))
                    })?,
                    amount_sats: input.amount_sats,
                })
            })
            .collect::<async_graphql::Result<Vec<_>>>()?;
        let spec = SpendSpec {
            inputs,
            outputs,
            fee_sats: self.fee_sats,
            change_output: self.change_output.map(|c| DomainChangeOutput {
                amount_sats: c.amount_sats,
                derivation_index: c.derivation_index,
            }),
        };
        Ok((self.wallet_id, spec))
    }
}

#[derive(SimpleObject)]
pub struct SpendProposePayload {
    pub psbt_session: PsbtSession,
}

impl From<DomainPsbtSession> for SpendProposePayload {
    fn from(session: DomainPsbtSession) -> Self {
        Self {
            psbt_session: PsbtSession::from(session),
        }
    }
}

#[derive(InputObject)]
pub struct SignedPsbtSubmitInput {
    pub session_id: PsbtSessionId,
    /// The signed PSBT, base64-encoded. Only the signatures are
    /// extracted and stored — never the submitted blob itself.
    pub signed_psbt: Base64,
}

#[derive(SimpleObject)]
pub struct SignedPsbtSubmitPayload {
    pub psbt_session: PsbtSession,
}

impl From<DomainPsbtSession> for SignedPsbtSubmitPayload {
    fn from(session: DomainPsbtSession) -> Self {
        Self {
            psbt_session: PsbtSession::from(session),
        }
    }
}
