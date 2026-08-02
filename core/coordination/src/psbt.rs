//! Validation of signer-submitted PSBTs.
//!
//! This is the security-critical code path of the signing flow. Signers
//! return a full PSBT document (BIP-174 is a *mergeable* format); before the
//! platform appends a `SignatureAdded` event it must prove the submission is
//! the original unsigned PSBT plus *only* additive partial signatures, and
//! that the submission is complete (every input signed): `add_signature` is
//! idempotent per fingerprint, so accepting a partial first upload would
//! permanently brick a multi-input session.
//!
//! Anything a signer's software changed beyond that — modified outputs,
//! stripped cosigner signatures, altered scripts — is rejected here, at the
//! use-case layer, before any event is recorded.

use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{Psbt, secp256k1};
use miniscript::psbt::PsbtExt;

#[derive(Debug, thiserror::Error)]
pub enum PsbtValidationError {
    #[error("psbt deserialization failed: {0}")]
    Deserialize(String),
    #[error("unsigned transaction was modified")]
    UnsignedTxModified,
    #[error("input/output count mismatch with original psbt")]
    InputOutputCountMismatch,
    #[error("partial signature from original psbt removed or altered at input {0}")]
    PartialSignatureRemoved(usize),
    #[error("submission adds no new partial signatures")]
    NoNewSignatures,
    #[error(
        "submission adds no partial signature for input {0}; a signer must sign every input \
         (accepting a partial submission would brick the session: add_signature is idempotent \
         per fingerprint, so the first upload is final)"
    )]
    IncompleteSubmission(usize),
    #[error("cannot compute sighash for input {index}: {reason}")]
    SighashComputation { index: usize, reason: String },
    #[error(
        "partial signature at input {0} uses a non-SIGHASH_ALL sighash type; \
         anything else would let the final transaction be malleated after signing"
    )]
    NonSigHashAllSighash(usize),
    #[error(
        "partial signature at input {0} failed cryptographic verification against the \
         unsigned PSBT's sighash — accepting it would permanently brick this signer's \
         slot (add_signature is idempotent per fingerprint, the first upload is final)"
    )]
    InvalidPartialSignature(usize),
}

pub fn parse_psbt(bytes: &[u8]) -> Result<Psbt, PsbtValidationError> {
    Psbt::deserialize(bytes).map_err(|e| PsbtValidationError::Deserialize(e.to_string()))
}

/// Verify that `signed` is `original` plus only additive partial signatures,
/// and that the submission is *complete*: every input must gain at least one
/// new partial signature. A signer signs the whole transaction (standard
/// SIGHASH_ALL behavior); allowing a partially-signed upload would brick the
/// session, because `add_signature` is idempotent per fingerprint and the
/// first upload sticks.
///
/// Every *new* partial signature is additionally verified cryptographically:
/// it must use `SIGHASH_ALL` and must verify against the sighash computed
/// from the *original* (platform-built, trusted) PSBT — never from the
/// submitted document, whose `witness_utxo`/`witness_script` fields are not
/// yet asserted immutable. This closes two holes:
///
/// - a signer uploading garbage/invalid signatures would permanently poison
///   their own slot (first upload is final), bricking any session whose
///   threshold requires them — a one-upload grief;
/// - a non-`SIGHASH_ALL` signature (`SIGHASH_NONE`, `SIGHASH_SINGLE`,
///   `SIGHASH_ANYONECANPAY`) would let the transaction be malleated after
///   the signer approved it.
///
/// Returns the number of new partial signatures added across all inputs.
///
/// TODO(security): bind the *new* partial signatures to the submitting
/// signer's fingerprint via `bip32_derivation` key sources, so a signer
/// cannot smuggle in signatures for other wallet members' keys.
/// TODO(security): also assert immutability of the non-signature fields we
/// care about (sighash types, redeem/witness scripts, proprietary keys) —
/// partial_sigs are not the only mutable-looking field in a PSBT.
pub fn validate_signed_submission(
    original: &Psbt,
    signed: &Psbt,
) -> Result<usize, PsbtValidationError> {
    if signed.unsigned_tx != original.unsigned_tx {
        return Err(PsbtValidationError::UnsignedTxModified);
    }
    if signed.inputs.len() != original.inputs.len()
        || signed.outputs.len() != original.outputs.len()
    {
        return Err(PsbtValidationError::InputOutputCountMismatch);
    }

    let secp = secp256k1::Secp256k1::verification_only();
    let mut cache = SighashCache::new(&original.unsigned_tx);

    let mut added = 0usize;
    let mut all_inputs_signed = true;
    for (idx, (orig_in, signed_in)) in original.inputs.iter().zip(signed.inputs.iter()).enumerate()
    {
        for (pk, sig) in &orig_in.partial_sigs {
            match signed_in.partial_sigs.get(pk) {
                Some(s) if s == sig => {}
                _ => return Err(PsbtValidationError::PartialSignatureRemoved(idx)),
            }
        }
        let mut added_here = 0usize;
        for (pk, sig) in &signed_in.partial_sigs {
            if orig_in.partial_sigs.contains_key(pk) {
                // already checked byte-equal against the original above
                continue;
            }
            if sig.sighash_type != EcdsaSighashType::All {
                return Err(PsbtValidationError::NonSigHashAllSighash(idx));
            }
            // Verify against the sighash of the *original* PSBT: the
            // submitted document's utxo/script fields are attacker-
            // controlled at this point, so a sighash derived from it
            // would prove nothing about validity at finalization time.
            let msg = original
                .sighash_msg(idx, &mut cache, None)
                .map_err(|e| PsbtValidationError::SighashComputation {
                    index: idx,
                    reason: e.to_string(),
                })?
                .to_secp_msg();
            secp.verify_ecdsa(&msg, &sig.signature, &pk.inner)
                .map_err(|_| PsbtValidationError::InvalidPartialSignature(idx))?;
            added_here += 1;
        }
        if added_here == 0 {
            all_inputs_signed = false;
        }
        added += added_here;
    }

    if added == 0 {
        return Err(PsbtValidationError::NoNewSignatures);
    }
    if !all_inputs_signed {
        let idx = original
            .inputs
            .iter()
            .zip(signed.inputs.iter())
            .position(|(orig_in, signed_in)| {
                signed_in.partial_sigs.len() == orig_in.partial_sigs.len()
            })
            .expect("all_inputs_signed is false, so some input gained no signature");
        return Err(PsbtValidationError::IncompleteSubmission(idx));
    }
    Ok(added)
}
