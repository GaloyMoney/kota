use bitcoin::Network;

/// Module-level configuration for the coordination service (lana-style:
/// one network per instance, arrives as a parameter at init).
#[derive(Debug, Clone)]
pub struct CoordinationConfig {
    /// The bitcoin network this instance coordinates on. Wallets,
    /// descriptors, and PSBTs are all scoped to it.
    pub network: Network,
}

impl CoordinationConfig {
    pub fn new(network: Network) -> Self {
        Self { network }
    }
}
