//! Wallet-side bitcoin logic: descriptors and PSBT construction.
//!
//! This is the logic the async PSBT-creation job runs: given the
//! [`SpendSpec`] recorded in `PsbtSessionEvent::Initialized`, a
//! `wsh(sortedmulti(NofM))` descriptor, and the funding UTXOs, build the
//! unsigned PSBT that quorum members will sign on their hardware wallets.
//!
//! Plain `sortedmulti` only — no miniscript spending conditions.

use std::str::FromStr;

use bitcoin::bip32::Fingerprint as KeyFingerprint;
use bitcoin::{
    Address, Amount, Network, OutPoint, Psbt, Sequence, Transaction, TxIn, TxOut, absolute,
    transaction::Version,
};
use miniscript::ForEachKey;
use miniscript::descriptor::{Descriptor, DescriptorPublicKey};
use miniscript::psbt::{PsbtExt, PsbtInputExt};

use crate::psbt_session::{OutPointRef, SpendSpec};

#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("WalletError - Miniscript: {0}")]
    Miniscript(#[from] miniscript::Error),
    #[error("WalletError - DescriptorConversion: {0}")]
    DescriptorConversion(#[from] miniscript::descriptor::ConversionError),
    #[error("WalletError - MissingFunding: no funding utxo for input {0}")]
    MissingFunding(OutPoint),
    #[error("WalletError - InvalidAddress: {0}")]
    InvalidAddress(String),
    #[error(
        "WalletError - AmountMismatch: inputs {inputs_sats} != outputs {outputs_sats} + fee {fee_sats}"
    )]
    AmountMismatch {
        inputs_sats: u64,
        outputs_sats: u64,
        fee_sats: u64,
    },
    #[error("WalletError - Psbt: {0}")]
    Psbt(String),
    #[error("WalletError - OutputUpdate: {0}")]
    OutputUpdate(#[from] miniscript::psbt::OutputUpdateError),
}

/// A wallet-owned coin being spent: the outpoint, its full `TxOut`
/// (amount + script, needed as `witness_utxo`), and where it lives in
/// the wallet's descriptor.
#[derive(Debug, Clone)]
pub struct FundingUtxo {
    pub outpoint: OutPointRef,
    pub txout: TxOut,
    pub derivation_index: u32,
}

impl From<&OutPointRef> for OutPoint {
    fn from(outpoint: &OutPointRef) -> Self {
        OutPoint {
            txid: outpoint.txid,
            vout: outpoint.vout,
        }
    }
}

/// Build a `wsh(sortedmulti(NofM))` descriptor from the policy's
/// keystores (xpubs with origin info, i.e. Sparrow `Keystore`s).
pub fn sortedmulti_wsh_descriptor(
    threshold: usize,
    keystores: Vec<DescriptorPublicKey>,
) -> Result<Descriptor<DescriptorPublicKey>, WalletError> {
    Ok(Descriptor::new_wsh_sortedmulti(threshold, keystores)?)
}

/// Build the unsigned PSBT for a spend.
///
/// Validates that every input has funding, that amounts balance
/// (inputs == outputs + change + fee), and fills each PSBT input with
/// the witness data and bip32 key sources hardware wallets need:
/// `witness_utxo`, `witness_script`, and `bip32_derivation`.
///
/// The change output's address is *derived* from the wallet descriptor
/// at the spec's `derivation_index` — never accepted from the caller —
/// and the change output's PSBT map is filled with `witness_script` and
/// `bip32_derivation` so signing devices that verify multisig change
/// have the key sources to do so.
pub fn build_unsigned_psbt(
    spend: &SpendSpec,
    descriptor: &Descriptor<DescriptorPublicKey>,
    funding: &[FundingUtxo],
    network: Network,
) -> Result<Psbt, WalletError> {
    let mut tx_inputs = Vec::with_capacity(spend.inputs.len());
    let mut derived_descriptors = Vec::with_capacity(spend.inputs.len());
    let mut witness_utxos = Vec::with_capacity(spend.inputs.len());
    let mut total_in = Amount::ZERO;

    for input in &spend.inputs {
        let outpoint = OutPoint::from(input);
        let utxo = funding
            .iter()
            .find(|f| OutPoint::from(&f.outpoint) == outpoint)
            .ok_or(WalletError::MissingFunding(outpoint))?;
        total_in += utxo.txout.value;
        tx_inputs.push(TxIn {
            previous_output: outpoint,
            // opt-in RBF: fee bumps are a first-class flow
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            ..Default::default()
        });
        witness_utxos.push(utxo.txout.clone());
        derived_descriptors.push(descriptor.at_derivation_index(utxo.derivation_index)?);
    }

    let mut tx_outputs = Vec::with_capacity(spend.outputs.len() + 1);
    let mut total_out = Amount::from_sat(spend.fee_sats);
    for output in &spend.outputs {
        let address = Address::from_str(&output.address)
            .map_err(|e| WalletError::InvalidAddress(e.to_string()))?
            .require_network(network)
            .map_err(|e| WalletError::InvalidAddress(e.to_string()))?;
        total_out += Amount::from_sat(output.amount_sats);
        tx_outputs.push(TxOut {
            value: Amount::from_sat(output.amount_sats),
            script_pubkey: address.script_pubkey(),
        });
    }

    // Change is derived from the wallet descriptor, never accepted as an
    // address from the caller: the coordinator is the one party that
    // certainly holds the descriptor, and hardware wallets cannot be
    // relied on to verify multisig change (many lack the storage for a
    // registered wallet policy), so this must be enforced here.
    let change_descriptor = spend
        .change_output
        .as_ref()
        .map(|change| descriptor.at_derivation_index(change.derivation_index))
        .transpose()?;
    if let (Some(change), Some(change_desc)) = (&spend.change_output, &change_descriptor) {
        total_out += Amount::from_sat(change.amount_sats);
        tx_outputs.push(TxOut {
            value: Amount::from_sat(change.amount_sats),
            script_pubkey: change_desc.script_pubkey(),
        });
    }

    if total_in != total_out {
        return Err(WalletError::AmountMismatch {
            inputs_sats: total_in.to_sat(),
            outputs_sats: (total_out - Amount::from_sat(spend.fee_sats)).to_sat(),
            fee_sats: spend.fee_sats,
        });
    }

    let n_outputs = tx_outputs.len();
    let tx = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: tx_inputs,
        output: tx_outputs,
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).map_err(|e| WalletError::Psbt(e.to_string()))?;

    for (idx, derived) in derived_descriptors.iter().enumerate() {
        psbt.inputs[idx].witness_utxo = Some(witness_utxos[idx].clone());
        psbt.inputs[idx].update_with_descriptor_unchecked(derived)?;
    }

    // Fill the change output's map with `witness_script` and
    // `bip32_derivation` key sources (BIP-174 output fields) so signing
    // devices that *can* verify multisig change have everything they
    // need. Also cross-checks the derived script against the tx output.
    if let Some(change_desc) = &change_descriptor {
        psbt.update_output_with_descriptor(n_outputs - 1, change_desc)?;
    }

    Ok(psbt)
}

/// Master fingerprints of the descriptor's keystores, for cross-checking
/// against a session's `Policy` (Sparrow: the wallet's keystore
/// fingerprints).
pub fn descriptor_fingerprints(
    descriptor: &Descriptor<DescriptorPublicKey>,
) -> Vec<KeyFingerprint> {
    let mut fingerprints = Vec::new();
    descriptor.for_each_key(|key| {
        let fingerprint = match key {
            DescriptorPublicKey::XPub(xkey) => xkey
                .origin
                .as_ref()
                .map(|(fingerprint, _)| *fingerprint)
                .unwrap_or_else(|| key.master_fingerprint()),
            _ => key.master_fingerprint(),
        };
        if !fingerprints.contains(&fingerprint) {
            fingerprints.push(fingerprint);
        }
        true
    });
    fingerprints
}
