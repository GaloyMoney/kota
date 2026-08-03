use async_graphql::*;

use crate::primitives::*;

pub use core_coordination::wallet::Wallet as DomainWallet;
use core_coordination::wallet::WalletStatus as DomainWalletStatus;

#[derive(Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletStatus {
    CollectingKeystores,
    Active,
    Cancelled,
}

impl From<DomainWalletStatus> for WalletStatus {
    fn from(status: DomainWalletStatus) -> Self {
        match status {
            DomainWalletStatus::CollectingKeystores => Self::CollectingKeystores,
            DomainWalletStatus::Active => Self::Active,
            DomainWalletStatus::Cancelled => Self::Cancelled,
        }
    }
}

#[derive(SimpleObject, Clone)]
pub struct KeystoreSubmission {
    user_id: UserId,
    keystore: String,
    /// Master fingerprint of the submitted keystore — the identity
    /// signatures are attributed to.
    fingerprint: String,
}

#[derive(SimpleObject, Clone)]
#[graphql(complex)]
pub struct Wallet {
    wallet_id: WalletId,
    network: String,
    threshold: u32,
    status: WalletStatus,
    /// The canonical descriptor, once the wallet is `Active`.
    descriptor: Option<String>,
    /// Content address of (network, canonical descriptor) — the
    /// idempotent-import key. Present once `Active`.
    descriptor_fingerprint: Option<String>,
    #[graphql(skip)]
    pub(super) entity: Arc<DomainWallet>,
}

impl From<DomainWallet> for Wallet {
    fn from(wallet: DomainWallet) -> Self {
        Self {
            wallet_id: wallet.id,
            network: wallet.network.to_string(),
            threshold: wallet.threshold,
            status: wallet.status().into(),
            descriptor: wallet.descriptor().map(|d| d.to_string()),
            descriptor_fingerprint: wallet.descriptor_fingerprint().map(|f| f.to_string()),
            entity: Arc::new(wallet),
        }
    }
}

#[ComplexObject]
impl Wallet {
    async fn participants(&self) -> Vec<UserId> {
        self.entity.participants().to_vec()
    }

    async fn pending_participants(&self) -> Vec<UserId> {
        self.entity.pending_participants()
    }

    async fn keystores(&self) -> Vec<KeystoreSubmission> {
        self.entity
            .submissions()
            .into_iter()
            .map(|(user_id, keystore)| KeystoreSubmission {
                user_id,
                fingerprint: self
                    .entity
                    .keystore_fingerprint_of(user_id)
                    .map(|f| f.to_string())
                    .unwrap_or_default(),
                keystore: keystore.to_string(),
            })
            .collect()
    }
}

#[derive(InputObject)]
pub struct WalletRegisterInput {
    pub threshold: u32,
    pub participants: Vec<UserId>,
}

#[derive(SimpleObject)]
pub struct WalletRegisterPayload {
    pub wallet: Wallet,
}

impl From<DomainWallet> for WalletRegisterPayload {
    fn from(wallet: DomainWallet) -> Self {
        Self {
            wallet: Wallet::from(wallet),
        }
    }
}

#[derive(InputObject)]
pub struct WalletKeystoreSubmitInput {
    pub wallet_id: WalletId,
    /// Descriptor public key (`[fingerprint/path]xpub…/0/*`).
    pub keystore: String,
}

#[derive(SimpleObject)]
pub struct WalletKeystoreSubmitPayload {
    pub wallet: Wallet,
}

impl From<DomainWallet> for WalletKeystoreSubmitPayload {
    fn from(wallet: DomainWallet) -> Self {
        Self {
            wallet: Wallet::from(wallet),
        }
    }
}

#[derive(InputObject)]
pub struct WalletKeystoreRemoveInput {
    pub wallet_id: WalletId,
    pub participant: UserId,
}

#[derive(SimpleObject)]
pub struct WalletKeystoreRemovePayload {
    pub wallet: Wallet,
}

impl From<DomainWallet> for WalletKeystoreRemovePayload {
    fn from(wallet: DomainWallet) -> Self {
        Self {
            wallet: Wallet::from(wallet),
        }
    }
}

#[derive(InputObject)]
pub struct WalletCancelInput {
    pub wallet_id: WalletId,
    pub reason: String,
}

#[derive(SimpleObject)]
pub struct WalletCancelPayload {
    pub wallet: Wallet,
}

impl From<DomainWallet> for WalletCancelPayload {
    fn from(wallet: DomainWallet) -> Self {
        Self {
            wallet: Wallet::from(wallet),
        }
    }
}
