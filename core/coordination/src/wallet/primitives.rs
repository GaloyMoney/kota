use serde::{Deserialize, Serialize};
use strum::{AsRefStr, Display, EnumString};

/// Lifecycle status, derived by folding the event stream.
///
/// Activation is terminal: a policy or keystore change produces a
/// different descriptor — and therefore a different
/// `descriptor_fingerprint`, i.e. a *different* wallet — so mutation
/// is modeled as retiring this wallet and registering a new one, never
/// as events on this aggregate.
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    AsRefStr,
    Display,
    EnumString,
)]
#[strum(serialize_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum WalletStatus {
    /// Policy registered; waiting for participants to submit keystores.
    /// No descriptor, no fingerprint, no address space yet.
    #[default]
    CollectingKeystores,
    /// All keystores collected; the canonical descriptor is derived.
    /// The wallet can receive funds and propose spends.
    Active,
    /// Abandoned before activation (quorum fell apart, registered by
    /// mistake). Terminal.
    Cancelled,
}
