//! Validation of signer-submitted PSBTs.
//!
//! This is the security-critical code path of the signing flow. Signers
//! return a full PSBT document (BIP-174 is a *mergeable* format); before the
//! platform appends a `SignatureAdded` event it must prove the submission is
//! the original unsigned PSBT plus *only* additive partial signatures from
//! the authenticated signer, and that the submission is complete (every
//! input signed): `add_signature` is idempotent per fingerprint, so
//! accepting a partial first upload would permanently brick a multi-input
//! session.
//!
//! Anything a signer's software changed beyond that — modified outputs,
//! stripped cosigner signatures, altered scripts, touched utxo/proprietary
//! fields — is rejected here, at the use-case layer, before any event is
//! recorded. And even for accepted submissions, only the extracted
//! signatures are used: the platform persists a PSBT rebuilt from the
//! original document, so attacker-controlled fields never reach
//! finalization.

use bitcoin::bip32::Fingerprint as KeyFingerprint;
use bitcoin::ecdsa::Signature as EcdsaSignature;
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{Psbt, PublicKey, secp256k1};
use miniscript::psbt::PsbtExt;

#[derive(Debug, thiserror::Error)]
pub enum PsbtValidationError {
    #[error("psbt deserialization failed: {0}")]
    Deserialize(String),
    #[error("psbt document is {size} bytes, exceeding the {max}-byte cap")]
    TooLarge { size: usize, max: usize },
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
    #[error("global psbt field (version/xpub/proprietary/unknown) was modified")]
    GlobalFieldModified,
    #[error(
        "non-signature field of input {0} was modified (utxo, scripts, sighash type, \
         key sources, preimages, proprietary/unknown keys)"
    )]
    InputFieldModified(usize),
    #[error("output map {0} was modified (scripts, key sources, proprietary/unknown keys)")]
    OutputFieldModified(usize),
}

/// Hard cap on accepted PSBT documents, in bytes (1 MiB).
///
/// Signer submissions are attacker-controlled bytes that get deserialized
/// and stored in content-addressed storage before any validation can run.
/// A cap keeps a hostile uploader from causing memory/CPU and storage
/// exhaustion. 1 MiB is generous: even a 100-input 15-of-15 P2WSH PSBT
/// with full key sources and partial signatures is ~250 KiB.
pub const MAX_PSBT_BYTES: usize = 1024 * 1024;

pub fn parse_psbt(bytes: &[u8]) -> Result<Psbt, PsbtValidationError> {
    if bytes.len() > MAX_PSBT_BYTES {
        return Err(PsbtValidationError::TooLarge {
            size: bytes.len(),
            max: MAX_PSBT_BYTES,
        });
    }
    Psbt::deserialize(bytes).map_err(|e| PsbtValidationError::Deserialize(e.to_string()))
}

/// Cryptographically verify one partial signature: it must use
/// `SIGHASH_ALL` and must verify against the sighash computed from the
/// *original* (platform-built, trusted) PSBT — never from a submitted
/// or stored document, whose `witness_utxo`/`witness_script` fields
/// are not asserted immutable.
fn verify_partial_sig(
    original: &Psbt,
    cache: &mut SighashCache<&bitcoin::Transaction>,
    secp: &secp256k1::Secp256k1<secp256k1::VerifyOnly>,
    index: usize,
    pubkey: &PublicKey,
    sig: &EcdsaSignature,
) -> Result<(), PsbtValidationError> {
    if sig.sighash_type != EcdsaSighashType::All {
        return Err(PsbtValidationError::NonSigHashAllSighash(index));
    }
    let msg = original
        .sighash_msg(index, cache, None)
        .map_err(|e| PsbtValidationError::SighashComputation {
            index,
            reason: e.to_string(),
        })?
        .to_secp_msg();
    secp.verify_ecdsa(&msg, &sig.signature, &pubkey.inner)
        .map_err(|_| PsbtValidationError::InvalidPartialSignature(index))?;
    Ok(())
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
/// All non-signature fields are asserted immutable: global
/// version/xpub/proprietary/unknown maps, every output map, and every input
/// field except `partial_sigs` (utxos, redeem/witness scripts, sighash
/// types, key sources, preimages, ...). This is deliberately strict —
/// signer software that decorates the PSBT with extra fields will be
/// rejected and must re-export — because (a) only the extracted signatures
/// are ever used, so extra fields carry no information the platform needs,
/// and (b) a submission with tampered fields is an unambiguous signal of
/// malicious or broken signer software that should halt the ceremony, not
/// be silently absorbed.
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
    if signed.version != original.version
        || signed.xpub != original.xpub
        || signed.proprietary != original.proprietary
        || signed.unknown != original.unknown
    {
        return Err(PsbtValidationError::GlobalFieldModified);
    }
    for (idx, (orig_out, signed_out)) in original
        .outputs
        .iter()
        .zip(signed.outputs.iter())
        .enumerate()
    {
        if signed_out != orig_out {
            return Err(PsbtValidationError::OutputFieldModified(idx));
        }
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
        // Everything except partial_sigs must be byte-identical to the
        // original input map.
        let mut signed_in_stripped = signed_in.clone();
        signed_in_stripped.partial_sigs = orig_in.partial_sigs.clone();
        if signed_in_stripped != *orig_in {
            return Err(PsbtValidationError::InputFieldModified(idx));
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
            // SIGHASH_ALL + cryptographic validity against the
            // original's sighash (helper docs).
            verify_partial_sig(original, &mut cache, &secp, idx, pk, sig)?;
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

/// Re-verify a platform-built merged blob (`original` plus one signer's
/// extracted signatures, as persisted at upload time) before it is used
/// at finalization.
///
/// Upload-time validation should make this redundant — but finalization
/// turns these bytes into a transaction that moves real money, and
/// `miniscript`'s `finalize` only checks that the script is *satisfied*,
/// not that the signatures *verify*: a corrupt or substituted blob would
/// otherwise be recorded as `Finalized` with the txid of a transaction
/// the network will reject, bricking the session. Re-verifying here
/// surfaces storage corruption as an error *before* any event is
/// recorded. Content-address verification ([`PsbtHash`]) detects swapped
/// bytes; this catches the subtler case of a blob that is structurally
/// intact but cryptographically wrong.
pub fn verify_merged_blob(original: &Psbt, merged: &Psbt) -> Result<(), PsbtValidationError> {
    if merged.unsigned_tx != original.unsigned_tx {
        return Err(PsbtValidationError::UnsignedTxModified);
    }
    if merged.inputs.len() != original.inputs.len() {
        return Err(PsbtValidationError::InputOutputCountMismatch);
    }

    let secp = secp256k1::Secp256k1::verification_only();
    let mut cache = SighashCache::new(&original.unsigned_tx);
    for (idx, (orig_in, merged_in)) in original.inputs.iter().zip(merged.inputs.iter()).enumerate()
    {
        for (pk, sig) in &merged_in.partial_sigs {
            // signatures already present in the original are trusted
            // (the platform built it); verify only what the blob added
            if orig_in.partial_sigs.contains_key(pk) {
                continue;
            }
            verify_partial_sig(original, &mut cache, &secp, idx, pk, sig)?;
        }
    }
    Ok(())
}
