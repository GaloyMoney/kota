//! DB round-trip for the Wallet repo. Skipped unless DATABASE_URL
//! points at a migrated database (`sqlx migrate run` from the repo root).

use core_coordination::{
    primitives::*,
    wallet::{NewWallet, WalletRepo, descriptor_fingerprint, sortedmulti_wsh_descriptor},
};

use bitcoin::Network;
use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::secp256k1::Secp256k1;
use es_entity::clock::ClockHandle;
use miniscript::descriptor::{DescriptorPublicKey, DescriptorXKey, Wildcard};
use std::str::FromStr;

const NETWORK: Network = Network::Regtest;

fn keystore(seed: u8) -> DescriptorPublicKey {
    let secp = Secp256k1::new();
    let xpriv = Xpriv::new_master(NETWORK, &[seed; 64]).unwrap();
    let account_path = DerivationPath::from_str("m/48'/0'/0'/2'").unwrap();
    let account_xpriv = xpriv.derive_priv(&secp, &account_path).unwrap();
    DescriptorPublicKey::XPub(DescriptorXKey {
        origin: Some((xpriv.fingerprint(&secp), account_path)),
        xkey: Xpub::from_priv(&secp, &account_xpriv),
        derivation_path: DerivationPath::from_str("m/0").unwrap(),
        wildcard: Wildcard::Unhardened,
    })
}

#[tokio::test]
async fn create_find_and_duplicate_round_trip() -> anyhow::Result<()> {
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL not set, skipping");
        return Ok(());
    };
    let pool = sqlx::PgPool::connect(&database_url).await?;
    let (clock, _ctrl) = ClockHandle::manual();
    let repo = WalletRepo::new(&pool, clock);

    let descriptor = sortedmulti_wsh_descriptor(2, vec![keystore(11), keystore(12), keystore(13)])?;
    let fingerprint = descriptor_fingerprint(&descriptor, NETWORK);

    // create + find by content address
    let wallet = repo
        .create(NewWallet::new(WalletId::new(), &descriptor, NETWORK))
        .await?;
    assert_eq!(wallet.descriptor_fingerprint(), fingerprint);
    assert_eq!(wallet.descriptor(), descriptor.to_string());

    let found = repo.find_by_descriptor_fingerprint(fingerprint).await?;
    assert_eq!(found.id, wallet.id);

    // re-importing the same wallet (same fingerprint) violates UNIQUE —
    // the use-case layer turns this into an idempotent find instead
    let duplicate = repo
        .create(NewWallet::new(WalletId::new(), &descriptor, NETWORK))
        .await;
    assert!(duplicate.is_err());

    // the same descriptor on a different network is a *different* wallet
    let other_network = repo
        .create(NewWallet::new(
            WalletId::new(),
            &descriptor,
            Network::Signet,
        ))
        .await?;
    assert_ne!(other_network.descriptor_fingerprint(), fingerprint);

    Ok(())
}
