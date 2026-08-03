//! Content-addressed blob storage.
//!
//! Dumb by design: `put`/`get`/`delete` keyed by the SHA-256 of the content.
//! The store has no logic of its own — the event log is the only index of
//! which hashes exist and what they mean, and lifecycle operations (deleting
//! a wallet's blobs) are driven by scanning events, never by listing the
//! store.
//!
//! Every fetch is self-verifying: the key is the digest of the content, so
//! callers recompute and compare ([`PsbtHash::digest_of`]).
//!
//! Real backends (GCS for deployed envs, local filesystem for dev) implement
//! this trait; [`InMemoryBlobStore`] serves tests.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::primitives::PsbtHash;

pub trait BlobStore {
    /// Store bytes, returning their content address.
    fn put<'a>(&'a self, bytes: &'a [u8]) -> impl Future<Output = PsbtHash> + Send + 'a;

    /// Fetch the blob at `hash`, if present.
    fn get<'a>(&'a self, hash: &'a PsbtHash) -> impl Future<Output = Option<Vec<u8>>> + Send + 'a;

    /// Delete the blob at `hash`. Returns whether anything was deleted.
    fn delete<'a>(&'a self, hash: &'a PsbtHash) -> impl Future<Output = bool> + Send + 'a;
}

#[derive(Debug, thiserror::Error)]
pub enum BlobFetchError {
    #[error("BlobFetchError - Missing: no blob stored at {0}")]
    Missing(PsbtHash),
    #[error("BlobFetchError - Corrupted: blob at {0} failed digest verification")]
    Corrupted(PsbtHash),
}

/// Fetch a blob and verify it against its content address: recompute
/// the digest, compare. Content-addressed fetch is self-verifying — a
/// mismatch means the storage backend is corrupt or tampered with, and
/// a miss for an event-log-referenced hash is a storage-integrity
/// error, not a routine cache miss. Every reader of stored blobs
/// should go through this rather than [`BlobStore::get`].
pub async fn fetch_verified(
    store: &impl BlobStore,
    hash: &PsbtHash,
) -> Result<Vec<u8>, BlobFetchError> {
    let bytes = store
        .get(hash)
        .await
        .ok_or(BlobFetchError::Missing(*hash))?;
    if PsbtHash::digest_of(&bytes) != *hash {
        return Err(BlobFetchError::Corrupted(*hash));
    }
    Ok(bytes)
}

/// In-memory store for tests. Clones share the same underlying map, so
/// a cloned service handle sees the same blobs.
#[derive(Default, Clone)]
pub struct InMemoryBlobStore(Arc<Mutex<HashMap<PsbtHash, Vec<u8>>>>);

impl BlobStore for InMemoryBlobStore {
    async fn put(&self, bytes: &[u8]) -> PsbtHash {
        let hash = PsbtHash::digest_of(bytes);
        self.0
            .lock()
            .expect("blob store mutex poisoned")
            .insert(hash, bytes.to_vec());
        hash
    }

    async fn get(&self, hash: &PsbtHash) -> Option<Vec<u8>> {
        self.0
            .lock()
            .expect("blob store mutex poisoned")
            .get(hash)
            .cloned()
    }

    async fn delete(&self, hash: &PsbtHash) -> bool {
        self.0
            .lock()
            .expect("blob store mutex poisoned")
            .remove(hash)
            .is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fetch_verified_round_trip() {
        let store = InMemoryBlobStore::default();
        let hash = store.put(b"unsigned-psbt").await;
        assert_eq!(
            fetch_verified(&store, &hash).await.unwrap(),
            b"unsigned-psbt"
        );
    }

    #[tokio::test]
    async fn fetch_verified_missing() {
        let store = InMemoryBlobStore::default();
        let hash = PsbtHash::digest_of(b"never-stored");
        assert!(matches!(
            fetch_verified(&store, &hash).await,
            Err(BlobFetchError::Missing(_))
        ));
    }

    #[tokio::test]
    async fn fetch_verified_corrupted() {
        let store = InMemoryBlobStore::default();
        let hash = PsbtHash::digest_of(b"original");
        // a corrupt/tampered backend returns different bytes for the key
        store.0.lock().unwrap().insert(hash, b"tampered".to_vec());
        assert!(matches!(
            fetch_verified(&store, &hash).await,
            Err(BlobFetchError::Corrupted(_))
        ));
    }
}
