//! Wallet-side bitcoin logic: descriptors and PSBT construction.
//!
//! This is the logic the async PSBT-creation job runs: given the
//! [`SpendSpec`] recorded in `PsbtSessionEvent::Initialized`, a
//! `wsh(sortedmulti(NofM))` descriptor, and the funding UTXOs, build the
//! unsigned PSBT that quorum members will sign on their hardware wallets.
//!
//! Plain `sortedmulti` only — no miniscript spending conditions.

mod entity;
pub mod repo;

pub use entity::{NewWallet, Wallet, WalletEvent};
pub use repo::WalletRepo;

use bitcoin::bip32::Fingerprint as KeyFingerprint;
use bitcoin::{
    Amount, Network, OutPoint, Psbt, Sequence, Transaction, TxIn, TxOut, absolute,
    transaction::Version,
};
use miniscript::descriptor::{Descriptor, DescriptorPublicKey};
use miniscript::{ForEachKey, Threshold};
use miniscript::psbt::PsbtExt;

use crate::primitives::DescriptorFingerprint;
use crate::psbt_session::{OutPointRef, SpendSpec};

#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("WalletError - Miniscript: {0}")]
    Miniscript(#[from] miniscript::Error),
    #[error("WalletError - Threshold: {0}")]
    Threshold(#[from] miniscript::ThresholdError),
    #[error("WalletError - NonDefiniteKey: {0}")]
    NonDefiniteKey(#[from] miniscript::descriptor::NonDefiniteKeyError),
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
    #[error("WalletError - UtxoUpdate: {0}")]
    UtxoUpdate(#[from] miniscript::psbt::UtxoUpdateError),
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
///
/// Keystores are sorted by their string form before construction:
/// `sortedmulti` sorts keys in the *script* but preserves import order
/// in the descriptor *string*, so without this canonicalization two
/// logically identical wallets would produce different descriptors —
/// and therefore different `descriptor_fingerprint`s.
pub fn sortedmulti_wsh_descriptor(
    threshold: usize,
    mut keystores: Vec<DescriptorPublicKey>,
) -> Result<Descriptor<DescriptorPublicKey>, WalletError> {
    keystores.sort_by_key(|k| k.to_string());
    let threshold = Threshold::new(threshold, keystores)?;
    Ok(Descriptor::new_wsh_sortedmulti(threshold)?)
}

/// Content address of a wallet: SHA-256 of the network and the
/// canonical descriptor string.
///
/// Canonicalization: the descriptor's own `Display` form minus the
/// `#checksum` suffix (the checksum is derived data, not identity).
/// Descriptors built via `sortedmulti_wsh_descriptor` are additionally
/// order-canonicalized at construction, so cosigner import order does
/// not affect the fingerprint; the network does (same xpubs, different
/// network, different wallet).
///
/// Deterministic by design — re-importing the same wallet yields the
/// same fingerprint, which `core_wallets.descriptor_fingerprint`
/// enforces with a UNIQUE constraint for idempotent creation. Note the
/// preimage is known-plaintext: anyone who learns the descriptor can
/// compute the fingerprint. Fine as an internal DB key; if it is ever
/// exposed externally, switch to an HMAC keyed by an instance secret.
pub fn descriptor_fingerprint(
    descriptor: &Descriptor<DescriptorPublicKey>,
    network: Network,
) -> DescriptorFingerprint {
    let string = descriptor.to_string();
    let canonical = string
        .split_once('#')
        .map(|(body, _)| body)
        .unwrap_or(&string);
    DescriptorFingerprint::digest_of(format!("{network}:{canonical}").as_bytes())
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
        let address = output
            .address
            .clone()
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
        // Checked update: errors unless the funding UTXO's script_pubkey
        // matches the descriptor at the claimed derivation index — a wrong
        // index or mismatched funding row is a validation error here, not
        // an inconsistent PSBT discovered later on a signing device.
        psbt.update_input_with_descriptor(idx, derived)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
    use bitcoin::secp256k1::Secp256k1;
    use miniscript::descriptor::{DescriptorXKey, Wildcard};
    use std::str::FromStr;

    const NETWORK: Network = Network::Regtest;

    fn keystore(seed: u8) -> DescriptorPublicKey {
        let secp = Secp256k1::new();
        let xpriv = Xpriv::new_master(NETWORK, &[seed; 64]).unwrap();
        let account_path = DerivationPath::from_str("m/48'/0'/0'/2'").unwrap();
        let account_xpriv = xpriv.derive_priv(&secp, &account_path).unwrap();
        DescriptorPublicKey::XPub(DescriptorXKey {
            origin: Some((xpriv.fingerprint(&secp), account_path)),
            xkey: Xpub::from_priv(&secp, &account_xpriv),
            derivation_path: DerivationPath::from_str("m/0").unwrap(),
            wildcard: Wildcard::Unhardened,
        })
    }

    fn two_of_three() -> Descriptor<DescriptorPublicKey> {
        sortedmulti_wsh_descriptor(2, vec![keystore(1), keystore(2), keystore(3)]).unwrap()
    }

    #[test]
    fn fingerprint_is_deterministic() {
        assert_eq!(
            descriptor_fingerprint(&two_of_three(), NETWORK),
            descriptor_fingerprint(&two_of_three(), NETWORK),
        );
    }

    #[test]
    fn fingerprint_depends_on_network() {
        let descriptor = two_of_three();
        assert_ne!(
            descriptor_fingerprint(&descriptor, Network::Testnet),
            descriptor_fingerprint(&descriptor, Network::Signet),
        );
    }

    #[test]
    fn fingerprint_ignores_checksum_suffix() {
        let with_checksum = two_of_three().to_string();
        let without_checksum = with_checksum.split_once('#').unwrap().0.to_string();

        let parsed_with: Descriptor<DescriptorPublicKey> = with_checksum.parse().unwrap();
        let parsed_without: Descriptor<DescriptorPublicKey> = without_checksum.parse().unwrap();

        assert_eq!(
            descriptor_fingerprint(&parsed_with, NETWORK),
            descriptor_fingerprint(&parsed_without, NETWORK),
        );
    }

    #[test]
    fn fingerprint_ignores_cosigner_import_order() {
        let forward =
            sortedmulti_wsh_descriptor(2, vec![keystore(1), keystore(2), keystore(3)]).unwrap();
        let reverse =
            sortedmulti_wsh_descriptor(2, vec![keystore(3), keystore(2), keystore(1)]).unwrap();
        assert_eq!(
            descriptor_fingerprint(&forward, NETWORK),
            descriptor_fingerprint(&reverse, NETWORK),
        );
    }

    #[test]
    fn fingerprint_depends_on_threshold() {
        let two =
            sortedmulti_wsh_descriptor(2, vec![keystore(1), keystore(2), keystore(3)]).unwrap();
        let three =
            sortedmulti_wsh_descriptor(3, vec![keystore(1), keystore(2), keystore(3)]).unwrap();
        assert_ne!(
            descriptor_fingerprint(&two, NETWORK),
            descriptor_fingerprint(&three, NETWORK),
        );
    }

    #[test]
    fn new_wallet_records_canonical_descriptor_and_fingerprint() {
        use es_entity::{IntoEvents, TryFromEvents};

        let descriptor = two_of_three();
        let new_wallet = NewWallet::new(crate::primitives::WalletId::new(), &descriptor, NETWORK);
        let expected_fingerprint = descriptor_fingerprint(&descriptor, NETWORK);

        let wallet = Wallet::try_from_events(new_wallet.into_events()).unwrap();
        assert_eq!(wallet.descriptor(), &descriptor);
        assert_eq!(wallet.descriptor_fingerprint(), expected_fingerprint);
    }

    #[test]
    fn descriptor_serializes_as_canonical_string() {
        // miniscript's serde impl uses the Display/FromStr string form —
        // the persisted event JSON is the standard BIP-380 text, not a
        // JSON structure.
        let descriptor = two_of_three();
        let event = crate::wallet::WalletEvent::Initialized {
            id: crate::primitives::WalletId::new(),
            descriptor_fingerprint: descriptor_fingerprint(&descriptor, NETWORK),
            descriptor: descriptor.clone(),
        };
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(
            json["descriptor"],
            serde_json::json!(descriptor.to_string())
        );

        let round_tripped: crate::wallet::WalletEvent = serde_json::from_value(json).unwrap();
        let crate::wallet::WalletEvent::Initialized {
            descriptor: parsed, ..
        } = round_tripped;
        assert_eq!(parsed, descriptor);
    }
}
