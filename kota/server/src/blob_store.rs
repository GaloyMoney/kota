//! Type erasure for the content-addressed blob store.
//!
//! `core-coordination` keeps `BlobStore` statically dispatched (the job
//! units and the use-case layer are generic over it), but the GraphQL
//! schema needs one *concrete* app type. [`DynBlobStore`] erases the
//! backend behind `Arc<dyn …>`; the binary chooses the implementation
//! (in-memory for dev until the GCS/filesystem backends land).

use futures::future::BoxFuture;
use std::sync::Arc;

use core_coordination::primitives::PsbtHash;
use core_coordination::storage::BlobStore;

trait ErasedBlobStore: Send + Sync {
    fn put<'a>(&'a self, bytes: &'a [u8]) -> BoxFuture<'a, PsbtHash>;
    fn get<'a>(&'a self, hash: &'a PsbtHash) -> BoxFuture<'a, Option<Vec<u8>>>;
    fn delete<'a>(&'a self, hash: &'a PsbtHash) -> BoxFuture<'a, bool>;
}

impl<T: BlobStore + Send + Sync> ErasedBlobStore for T {
    fn put<'a>(&'a self, bytes: &'a [u8]) -> BoxFuture<'a, PsbtHash> {
        Box::pin(BlobStore::put(self, bytes))
    }

    fn get<'a>(&'a self, hash: &'a PsbtHash) -> BoxFuture<'a, Option<Vec<u8>>> {
        Box::pin(BlobStore::get(self, hash))
    }

    fn delete<'a>(&'a self, hash: &'a PsbtHash) -> BoxFuture<'a, bool> {
        Box::pin(BlobStore::delete(self, hash))
    }
}

/// A `BlobStore` whose backend is chosen at runtime.
pub struct DynBlobStore(Arc<dyn ErasedBlobStore>);

impl DynBlobStore {
    pub fn new<B: BlobStore + Send + Sync + 'static>(store: B) -> Self {
        Self(Arc::new(store))
    }
}

impl BlobStore for DynBlobStore {
    fn put<'a>(&'a self, bytes: &'a [u8]) -> impl Future<Output = PsbtHash> + Send + 'a {
        self.0.put(bytes)
    }

    fn get<'a>(&'a self, hash: &'a PsbtHash) -> impl Future<Output = Option<Vec<u8>>> + Send + 'a {
        self.0.get(hash)
    }

    fn delete<'a>(&'a self, hash: &'a PsbtHash) -> impl Future<Output = bool> + Send + 'a {
        self.0.delete(hash)
    }
}
