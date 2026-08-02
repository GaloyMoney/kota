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

use bitcoin::bip32::Fingerprint as KeyFingerprint;
use bitcoin::ecdsa::Signature as EcdsaSignature;
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{Psbt, PublicKey, secp256k1};
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
    #[error(
        "partial signature at input {index} is for pubkey {pubkey}, which is not bound to \
         keystore {expected} in the original PSBT's bip32 derivation — a signer may only \
         contribute signatures for their own keystore"
    )]
    SignatureNotBoundToSigner {
        index: usize,
        pubkey: PublicKey,
        expected: KeyFingerprint,
    },
}

pub fn parse_psbt(bytes: &[u8]) -> Result<Psbt, PsbtValidationError> {
    Psbt::deserialize(bytes).map_err(|e| PsbtValidationError::Deserialize(e.to_string()))
}

/// A partial signature extracted from a validated submission, ready to be
/// merged into the platform's copy of the original PSBT.
#[derive(Debug, Clone)]
pub struct ExtractedSignature {
    pub input_index: usize,
    pub pubkey: PublicKey,
    pub signature: EcdsaSignature,
}

/// Verify that `signed` is `original` plus only additive partial signatures
/// *from the claimed signer*, and that the submission is *complete*: every
/// input must gain at least one new partial signature. A signer signs the
/// whole transaction (standard SIGHASH_ALL behavior); allowing a
/// partially-signed upload would brick the session, because `add_signature`
/// is idempotent per fingerprint and the first upload sticks.
///
/// `expected_fingerprint` is the keystore fingerprint the use-case layer
/// authenticated the uploader as. Every new partial signature must be for a
/// pubkey whose `bip32_derivation` key source *in the original PSBT* carries
/// that fingerprint. This is what stops signature smuggling: partial sigs
/// are just bytes — anyone who fetched a cosigner's uploaded blob could
/// otherwise re-upload that cosigner's signatures as their own submission,
/// corrupting the audit trail (`Finalized::sigs_used` claims to record who
/// authorized the spend).
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
/// Returns the extracted new partial signatures. The caller MUST persist a
/// PSBT rebuilt via [`merge_partial_sigs`] from the original plus these
/// signatures — never the submitted document, whose non-signature fields
/// are attacker-controlled.
///
/// TODO(security): also assert immutability of the non-signature fields we
/// care about (sighash types, redeem/witness scripts, proprietary keys) —
/// partial_sigs are not the only mutable-looking field in a PSBT.
pub fn validate_signed_submission(
    original: &Psbt,
    signed: &Psbt,
    expected_fingerprint: &KeyFingerprint,
) -> Result<Vec<ExtractedSignature>, PsbtValidationError> {
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

    let mut extracted = Vec::new();
    let mut first_incomplete_input = None;
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
            // Bind the signature to the authenticated signer via the
            // *original* PSBT's key sources (platform-built, trusted):
            // the submitting document's own bip32_derivation is
            // attacker-controlled and proves nothing.
            match orig_in.bip32_derivation.get(&pk.inner) {
                Some((fingerprint, _)) if fingerprint == expected_fingerprint => {}
                _ => {
                    return Err(PsbtValidationError::SignatureNotBoundToSigner {
                        index: idx,
                        pubkey: *pk,
                        expected: *expected_fingerprint,
                    });
                }
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
            extracted.push(ExtractedSignature {
                input_index: idx,
                pubkey: *pk,
                signature: *sig,
            });
        }
        if added_here == 0 && first_incomplete_input.is_none() {
            first_incomplete_input = Some(idx);
        }
    }

    if extracted.is_empty() {
        return Err(PsbtValidationError::NoNewSignatures);
    }
    if let Some(idx) = first_incomplete_input {
        return Err(PsbtValidationError::IncompleteSubmission(idx));
    }
    Ok(extracted)
}

/// Rebuild the merged PSBT the platform persists: the *original*
/// platform-built document plus exactly the validated new partial
/// signatures. The submitted document itself is never stored or
/// finalized — only these extracted signatures cross the trust boundary.
pub fn merge_partial_sigs(original: &Psbt, new_sigs: &[ExtractedSignature]) -> Psbt {
    let mut merged = original.clone();
    for sig in new_sigs {
        merged.inputs[sig.input_index]
            .partial_sigs
            .insert(sig.pubkey, sig.signature);
    }
    merged
}
