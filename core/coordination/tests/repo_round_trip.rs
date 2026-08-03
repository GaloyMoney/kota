//! DB round-trip for the PsbtSession repo. Skipped unless DATABASE_URL
//! points at a migrated database (`sqlx migrate run` from the repo root).

use core_coordination::{
    primitives::*,
    psbt_session::{
        NewPsbtSession, OutPointRef, PsbtSessionRepo, PsbtSessionStatus, SpendOutput, SpendSpec,
    },
    wallet::{NewWallet, Wallet, keystore_fingerprint},
};

use bitcoin::Network;
use bitcoin::bip32::{DerivationPath, Fingerprint as KeyFingerprint, Xpriv, Xpub};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::Secp256k1;
use chrono::{DateTime, Utc};
use es_entity::clock::ClockHandle;
use es_entity::{IntoEvents, TryFromEvents};
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

fn fp(byte: u8) -> KeyFingerprint {
    keystore_fingerprint(&keystore(byte))
}

/// An in-memory active 2-of-3 wallet (seeds 1, 2, 3) to propose against.
fn active_wallet() -> Wallet {
    let participants: Vec<UserId> = (0..3).map(|_| UserId::new()).collect();
    let mut wallet = Wallet::try_from_events(
        NewWallet::new(WalletId::new(), NETWORK, 2, participants.clone())
            .unwrap()
            .into_events(),
    )
    .unwrap();
    for (seed, participant) in [1u8, 2, 3].iter().zip(participants) {
        let _ = wallet.add_keystore(keystore(*seed), participant).unwrap();
    }
    wallet
}

#[tokio::test]
async fn create_and_update_round_trip() -> anyhow::Result<()> {
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL not set, skipping");
        return Ok(());
    };
    let pool = sqlx::PgPool::connect(&database_url).await?;
    let (clock, _ctrl) = ClockHandle::manual();
    let repo = PsbtSessionRepo::new(&pool, clock);

    let new_session = NewPsbtSession::try_new(
        PsbtSessionId::new(),
        &active_wallet(),
        UserId::new(),
        SpendSpec {
            inputs: vec![OutPointRef {
                txid: bitcoin::Txid::from_byte_array([100; 32]),
                vout: 0,
            }],
            outputs: vec![SpendOutput {
                address: "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
                    .parse()
                    .unwrap(),
                amount_sats: 50_000,
            }],
            fee_sats: 500,
            change_output: None,
        },
        DateTime::<Utc>::from_timestamp(2_000_000_000, 0).unwrap(),
        DateTime::<Utc>::from_timestamp(1_900_000_000, 0).unwrap(),
    )?;

    let mut session = repo.create(new_session).await?;
    assert_eq!(session.status(), PsbtSessionStatus::Pending);

    // the async creation job runs: PSBT built, uploaded, hash recorded
    session
        .record_psbt_created(
            PsbtHash::digest_of(b"unsigned-psbt"),
            DateTime::<Utc>::from_timestamp(1_900_000_000, 0).unwrap(),
        )?
        .unwrap();
    let persisted = repo.update(&mut session).await?;
    assert_eq!(persisted, 1, "one PsbtCreated event persisted");
    assert_eq!(session.status(), PsbtSessionStatus::Collecting);

    session
        .add_signature(
            fp(1),
            PsbtHash::digest_of(b"signed-psbt-1"),
            DateTime::<Utc>::from_timestamp(1_900_000_000, 0).unwrap(),
        )?
        .unwrap();

    let persisted = repo.update(&mut session).await?;
    assert_eq!(persisted, 1, "one SignatureAdded event persisted");
    assert_eq!(session.signature_count(), 1);

    let found = repo.find_by_id(session.id).await?;
    assert_eq!(found.signatures()[0].fingerprint, fp(1));
    assert_eq!(found.status(), PsbtSessionStatus::Collecting);

    Ok(())
}
