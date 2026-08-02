use serde::{Deserialize, Serialize};
use sha2::Digest;

es_entity::entity_id! {
    PsbtSessionId,
    WalletId;
}

/// Content hash (SHA-256) of a serialized PSBT or final transaction blob.
///
/// Blobs live in object storage; events carry only this hash plus a
/// [`BlobRef`]. The hash is the audit anchor: anyone holding the blob can
/// prove it is exactly what the event refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
        write!(f, "{}", hex::encode(self.0))
    }
}

// Minimal hex encoding to avoid a hex crate dependency for Display.
mod hex {
    pub fn encode(bytes: [u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Reference to a blob (PSBT / raw transaction) in object storage.
///
/// PSBTs are documents, not values — they are too large and too sensitive
/// to embed in events. The platform stores them in object storage with
/// lifecycle controls (crypto-shredding on data-deletion requests) while
/// the event log keeps the immutable hash-chained reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobRef(String);

impl BlobRef {
    pub fn new(key: impl Into<String>) -> Self {
        Self(key.into())
    }
}

impl std::fmt::Display for BlobRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for BlobRef {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}
