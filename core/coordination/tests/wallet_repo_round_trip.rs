//! DB round-trip for the Wallet repo. Skipped unless DATABASE_URL
//! points at a migrated database (`sqlx migrate run` from the repo root).

use core_coordination::{
    primitives::*,
    wallet::{
        NewWallet, WalletRepo, WalletStatus, descriptor_fingerprint, sortedmulti_wsh_descriptor,
    },
};

use bitcoin::Network;
use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::secp256k1::Secp256k1;
use es_entity::clock::ClockHandle;
use miniscript::descriptor::{DescriptorPublicKey, DescriptorXKey, Wildcard};
use std::str::FromStr;

const NETWORK: Network = Network::Regtest;
const SEEDS: [u8; 3] = [11, 12, 13];

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
async fn keystore_collection_activation_and_duplicate_round_trip() -> anyhow::Result<()> {
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL not set, skipping");
        return Ok(());
    };
    let pool = sqlx::PgPool::connect(&database_url).await?;
    // deterministic keystores => deterministic fingerprint; reset so
    // repeated runs against a persistent dev DB don't collide
    sqlx::query("DELETE FROM core_wallet_events")
        .execute(&pool)
        .await?;
    sqlx::query("DELETE FROM core_wallets")
        .execute(&pool)
        .await?;
    let (clock, _ctrl) = ClockHandle::manual();
    let repo = WalletRepo::new(&pool, clock);

    let descriptor = sortedmulti_wsh_descriptor(2, SEEDS.iter().map(|s| keystore(*s)).collect())?;
    let fingerprint = descriptor_fingerprint(&descriptor, NETWORK);

    // create: policy only, no fingerprint yet
    let participants: Vec<UserId> = (0..3).map(|_| UserId::new()).collect();
    let mut wallet = repo
        .create(NewWallet::new(
            WalletId::new(),
            NETWORK,
            2,
            participants.clone(),
        )?)
        .await?;
    assert_eq!(wallet.status(), WalletStatus::CollectingKeystores);
    assert_eq!(wallet.descriptor_fingerprint(), None);

    // collect keystores one by one; the last one activates the wallet
    for (seed, participant) in SEEDS.iter().zip(&participants) {
        let _ = wallet.add_keystore(keystore(*seed), *participant)?;
        repo.update(&mut wallet).await?;
    }
    assert_eq!(wallet.status(), WalletStatus::Active);
    assert_eq!(wallet.descriptor_fingerprint(), Some(fingerprint));
    assert_eq!(wallet.descriptor(), Some(&descriptor));

    // find by content address
    let found = repo
        .find_by_descriptor_fingerprint(Some(fingerprint))
        .await?;
    assert_eq!(found.id, wallet.id);
    assert_eq!(found.status(), WalletStatus::Active);

    // a second wallet converging on the same descriptor collides on the
    // UNIQUE fingerprint at activation — the use-case layer turns this
    // into an idempotent find of the existing wallet
    let mut duplicate = repo
        .create(NewWallet::new(
            WalletId::new(),
            NETWORK,
            2,
            participants.clone(),
        )?)
        .await?;
    for (seed, participant) in SEEDS.iter().zip(&participants) {
        let _ = duplicate.add_keystore(keystore(*seed), *participant)?;
    }
    assert!(repo.update(&mut duplicate).await.is_err());

    // the same policy and keys on a different network is a *different*
    // wallet: different fingerprint, no collision
    let mut other_network = repo
        .create(NewWallet::new(
            WalletId::new(),
            Network::Signet,
            2,
            participants.clone(),
        )?)
        .await?;
    for (seed, participant) in SEEDS.iter().zip(&participants) {
        let _ = other_network.add_keystore(keystore(*seed), *participant)?;
    }
    repo.update(&mut other_network).await?;
    assert_ne!(other_network.descriptor_fingerprint(), Some(fingerprint));

    Ok(())
}
