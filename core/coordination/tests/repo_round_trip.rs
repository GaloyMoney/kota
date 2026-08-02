//! DB round-trip for the PsbtSession repo. Skipped unless DATABASE_URL
//! points at a migrated database (`sqlx migrate run` from the repo root).

use core_coordination::{
    primitives::*,
    psbt_session::{
        NewPsbtSession, OutPointRef, Policy, PsbtSessionRepo, PsbtSessionStatus, SpendOutput,
        SpendSpec,
    },
};

use bitcoin::bip32::Fingerprint as KeyFingerprint;
use bitcoin::hashes::Hash;
use chrono::{DateTime, Utc};
use es_entity::clock::ClockHandle;

fn fp(byte: u8) -> KeyFingerprint {
    KeyFingerprint::from([byte, byte, byte, byte])
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
        WalletId::new(),
        UserId::new(),
        SpendSpec {
            inputs: vec![OutPointRef {
                txid: bitcoin::Txid::from_byte_array([100; 32]),
                vout: 0,
            }],
            outputs: vec![SpendOutput {
                address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
                    .parse()
                    .unwrap(),
                amount_sats: 50_000,
            }],
            fee_sats: 500,
            change_output: None,
        },
        Policy {
            threshold: 2,
            keystores: vec![fp(1), fp(2), fp(3)],
        },
        DateTime::<Utc>::from_timestamp(2_000_000_000, 0).unwrap(),
    )?;

    let mut session = repo.create(new_session).await?;
    assert_eq!(session.status(), PsbtSessionStatus::Pending);

    // the async creation job runs: PSBT built, uploaded, hash recorded
    session
        .record_psbt_created(PsbtHash::digest_of(b"unsigned-psbt"))?
        .unwrap();
    let persisted = repo.update(&mut session).await?;
    assert_eq!(persisted, 1, "one PsbtCreated event persisted");
    assert_eq!(session.status(), PsbtSessionStatus::Collecting);

    session
        .add_signature(fp(1), PsbtHash::digest_of(b"signed-psbt-1"))?
        .unwrap();

    let persisted = repo.update(&mut session).await?;
    assert_eq!(persisted, 1, "one SignatureAdded event persisted");
    assert_eq!(session.signature_count(), 1);

    let found = repo.find_by_id(session.id).await?;
    assert_eq!(found.signatures()[0].fingerprint, fp(1));
    assert_eq!(found.status(), PsbtSessionStatus::Collecting);

    Ok(())
}
