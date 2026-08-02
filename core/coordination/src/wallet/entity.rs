//! The wallet aggregate: a registered multisig wallet.
//!
//! Identity is deliberately two-layered (see the module docs on
//! `descriptor_fingerprint`): `WalletId` is a framework-internal UUID
//! (es_entity PK, event references), while `descriptor_fingerprint` is
//! the deterministic content address of (network, canonical
//! descriptor), UNIQUE in the database — re-importing the same wallet
//! is an idempotent no-op at the use-case layer, not a duplicate row.

use derive_builder::Builder;
use serde::{Deserialize, Serialize};

use es_entity::*;

use bitcoin::Network;
use miniscript::descriptor::{Descriptor, DescriptorPublicKey};

use crate::primitives::{DescriptorFingerprint, WalletId};

#[derive(EsEvent, Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[es_event(id = "WalletId")]
pub enum WalletEvent {
    Initialized {
        id: WalletId,
        /// Canonical descriptor string (with `#checksum`), as produced
        /// by `Descriptor::to_string()`.
        descriptor: String,
        /// Content address of (network, canonical descriptor). See
        /// `crate::wallet::descriptor_fingerprint`.
        descriptor_fingerprint: DescriptorFingerprint,
    },
}

#[derive(EsEntity, Builder)]
#[builder(pattern = "owned", build_fn(error = "EntityHydrationError"))]
pub struct Wallet {
    pub id: WalletId,
    pub descriptor: String,
    pub descriptor_fingerprint: DescriptorFingerprint,
    events: EntityEvents<WalletEvent>,
}

impl Wallet {
    pub fn descriptor(&self) -> &str {
        &self.descriptor
    }

    pub fn descriptor_fingerprint(&self) -> DescriptorFingerprint {
        self.descriptor_fingerprint
    }
}

impl TryFromEvents<WalletEvent> for Wallet {
    fn try_from_events(events: EntityEvents<WalletEvent>) -> Result<Self, EntityHydrationError> {
        let mut builder = WalletBuilder::default();
        for event in events.iter_all() {
            match event {
                WalletEvent::Initialized {
                    id,
                    descriptor,
                    descriptor_fingerprint,
                } => {
                    builder = builder
                        .id(*id)
                        .descriptor(descriptor.clone())
                        .descriptor_fingerprint(*descriptor_fingerprint);
                }
            }
        }
        builder.events(events).build()
    }
}

#[derive(Debug, Builder)]
pub struct NewWallet {
    #[builder(setter(into))]
    pub(super) id: WalletId,
    descriptor: String,
    descriptor_fingerprint: DescriptorFingerprint,
}

impl NewWallet {
    pub fn builder() -> NewWalletBuilder {
        NewWalletBuilder::default()
    }

    /// Register a wallet from its (parsed, validated) descriptor.
    /// Infallible: descriptor validation happens upstream at the
    /// use-case layer; the fingerprint is pure derivation.
    pub fn new(
        id: WalletId,
        descriptor: &Descriptor<DescriptorPublicKey>,
        network: Network,
    ) -> Self {
        Self {
            id,
            descriptor: descriptor.to_string(),
            descriptor_fingerprint: super::descriptor_fingerprint(descriptor, network),
        }
    }

    pub(super) fn descriptor_fingerprint(&self) -> DescriptorFingerprint {
        self.descriptor_fingerprint
    }
}

impl IntoEvents<WalletEvent> for NewWallet {
    fn into_events(self) -> EntityEvents<WalletEvent> {
        EntityEvents::init(
            self.id,
            [WalletEvent::Initialized {
                id: self.id,
                descriptor: self.descriptor,
                descriptor_fingerprint: self.descriptor_fingerprint,
            }],
        )
    }
}
