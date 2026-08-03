use bitcoin::Network;

/// Module-level configuration for the coordination service (lana-style:
/// one network per instance, arrives as a parameter at init).
#[derive(Debug, Clone)]
pub struct CoordinationConfig {
    /// The bitcoin network this instance coordinates on. Wallets,
    /// descriptors, and PSBTs are all scoped to it.
    pub network: Network,
    /// How long a proposed spend collects signatures before the (future)
    /// expiry job cancels it. Fee market drift and UTXO availability
    /// bound how long a proposal stays meaningful.
    pub proposal_ttl: chrono::Duration,
}

impl CoordinationConfig {
    pub const DEFAULT_PROPOSAL_TTL: chrono::Duration = chrono::Duration::hours(24);

    pub fn new(network: Network) -> Self {
        Self {
            network,
            proposal_ttl: Self::DEFAULT_PROPOSAL_TTL,
        }
    }
}
