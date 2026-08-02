use serde::{Deserialize, Serialize};
use sha2::Digest;

es_entity::entity_id! {
    PsbtSessionId,
    WalletId;
}

es_entity::entity_id! { UserId }

/// Content address (SHA-256) of a PSBT or final-transaction blob.
///
/// Blobs live in dumb content-addressed storage (GCS in deployed envs, local
/// filesystem in dev): `put(hash, bytes)` / `get(hash)` / `delete(hash)`.
/// The storage layer has no logic of its own — the event log is the only
/// index of which hashes exist and what they mean, and lifecycle decisions
/// (e.g. deleting blobs for a wallet) are driven by scanning events, never
/// by listing the bucket.
///
/// Because the hash is both the key and the integrity anchor, every fetch
/// is self-verifying: recompute the digest and compare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PsbtHash([u8; 32]);

impl PsbtHash {
    pub fn digest_of(bytes: &[u8]) -> Self {
        let digest = sha2::Sha256::digest(bytes);
        let mut inner = [0u8; 32];
        inner.copy_from_slice(&digest);
        Self(inner)
    }
}

impl std::fmt::Display for PsbtHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl std::str::FromStr for PsbtHash {
    type Err = PsbtHashParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 64 {
            return Err(PsbtHashParseError);
        }
        let mut inner = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hi = (chunk[0] as char).to_digit(16).ok_or(PsbtHashParseError)?;
            let lo = (chunk[1] as char).to_digit(16).ok_or(PsbtHashParseError)?;
            inner[i] = ((hi << 4) | lo) as u8;
        }
        Ok(Self(inner))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid psbt hash: expected 64 lowercase hex characters")]
pub struct PsbtHashParseError;
