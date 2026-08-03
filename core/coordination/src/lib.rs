//! Coordination layer for multi-user bitcoin multisig custody.
//!
//! The platform never holds key material and never signs. It coordinates
//! the PSBT lifecycle (propose -> collect signatures -> finalize -> broadcast
//! -> confirm) and keeps an immutable audit trail of who did what.

pub mod app;
pub mod jobs;
pub mod primitives;
pub mod psbt;
pub mod psbt_session;
pub mod storage;
pub mod wallet;
