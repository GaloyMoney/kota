//! Use-case layer integration tests: the full coordination flow driven
//! through `Coordination` commands with the real `job` executor running
//! (spawn -> poll -> execute), exactly like production wiring.
//!
//! Each test gets its own database (created from DATABASE_URL's server),
//! so tests parallelize safely: an executor only ever claims jobs from
//! its own test's database. Skipped unless DATABASE_URL is set.

use core_coordination::{
    jobs::{FundingUtxoProvider, JobsError},
    primitives::*,
    psbt::parse_psbt,
    psbt_session::{
        ChangeOutput, OutPointRef, PsbtSession, PsbtSessionError, PsbtSessionStatus, SpendOutput,
        SpendSpec,
    },
    storage::{BlobStore, InMemoryBlobStore},
    wallet::{FundingUtxo, Wallet, WalletError, WalletStatus},
};
use kota_app::{Coordination, CoordinationConfig, CoordinationError};

use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Amount, Network, Transaction, TxOut, consensus};
use miniscript::descriptor::{DescriptorPublicKey, DescriptorXKey, Wildcard};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const NETWORK: Network = Network::Regtest;

fn make_keystore(seed: &[u8]) -> (DescriptorPublicKey, Xpriv) {
    let secp = Secp256k1::new();
    let xpriv = Xpriv::new_master(NETWORK, seed).unwrap();
    let account_path = DerivationPath::from_str("m/48'/0'/0'/2'").unwrap();
    let account_xpriv = xpriv.derive_priv(&secp, &account_path).unwrap();
    let keystore = DescriptorPublicKey::XPub(DescriptorXKey {
        origin: Some((xpriv.fingerprint(&secp), account_path)),
        xkey: Xpub::from_priv(&secp, &account_xpriv),
        derivation_path: DerivationPath::from_str("m/0").unwrap(),
        wildcard: Wildcard::Unhardened,
    });
    (keystore, xpriv)
}

/// Funding is wallet-descriptor-dependent, so the provider is filled in
/// by the test once the wallet is active.
#[derive(Default, Clone)]
struct StaticFunding(Arc<Mutex<Vec<FundingUtxo>>>);

impl StaticFunding {
    fn set(&self, utxos: Vec<FundingUtxo>) {
        *self.0.lock().unwrap() = utxos;
    }
}

impl FundingUtxoProvider for StaticFunding {
    async fn funding_utxos(
        &self,
        _wallet: &Wallet,
        _inputs: &[OutPointRef],
    ) -> Result<Vec<FundingUtxo>, JobsError> {
        Ok(self.0.lock().unwrap().clone())
    }
}

struct Fixture {
    app: Coordination<InMemoryBlobStore>,
    jobs: job::Jobs,
    blobs: Arc<InMemoryBlobStore>,
    funding: StaticFunding,
    participants: Vec<UserId>,
    keystores: Vec<DescriptorPublicKey>,
    xprivs: Vec<Xpriv>,
}

impl Fixture {
    async fn new() -> Option<Self> {
        let Ok(database_url) = std::env::var("DATABASE_URL") else {
            eprintln!("DATABASE_URL not set, skipping");
            return None;
        };
        // per-test database: full isolation between parallel tests
        let db_name = format!("kota_test_{}", uuid::Uuid::new_v4().simple());
        let admin = sqlx::PgPool::connect(&database_url).await.unwrap();
        sqlx::query(&format!("CREATE DATABASE {db_name}"))
            .execute(&admin)
            .await
            .unwrap();
        let (base, _) = database_url
            .rsplit_once('/')
            .expect("DATABASE_URL has a database path");
        let test_url = format!("{base}/{db_name}");
        let pool = sqlx::PgPool::connect(&test_url).await.unwrap();
        sqlx::migrate!("../../migrations").run(&pool).await.unwrap();

        let mut jobs = job::Jobs::init(
            job::JobSvcConfig::builder()
                .pool(pool.clone())
                .build()
                .unwrap(),
        )
        .await
        .unwrap();
        let blobs = Arc::new(InMemoryBlobStore::default());
        let funding = StaticFunding::default();
        let app = Coordination::init(
            &pool,
            &mut jobs,
            blobs.clone(),
            Arc::new(funding.clone()),
            CoordinationConfig::new(NETWORK),
        );
        jobs.start_poll().await.unwrap();

        let participants = (0..3).map(|_| UserId::new()).collect();
        let (keystores, xprivs) = (0..3)
            .map(|_| *uuid::Uuid::new_v4().as_bytes())
            .map(|seed| {
                let (keystore, xpriv) = make_keystore(&seed);
                (keystore, xpriv)
            })
            .unzip();
        Some(Self {
            app,
            jobs,
            blobs,
            funding,
            participants,
            keystores,
            xprivs,
        })
    }

    /// A fully activated 2-of-3 wallet (keystores submitted in order).
    async fn active_wallet(&self) -> Wallet {
        let wallet = self
            .app
            .register_wallet(2, self.participants.clone())
            .await
            .unwrap();
        for i in 0..3 {
            self.app
                .submit_keystore(wallet.id, self.participants[i], self.keystores[i].clone())
                .await
                .unwrap();
        }
        let wallet = self.app.find_wallet(wallet.id).await.unwrap();
        assert_eq!(wallet.status(), WalletStatus::Active);
        wallet
    }

    /// A session driven to Collecting by the real PSBT-creation job.
    async fn collecting_session(&self) -> (PsbtSession, Wallet) {
        let wallet = self.active_wallet().await;
        let descriptor = wallet.descriptor().unwrap().clone();

        let funding_txid = bitcoin::Txid::from_byte_array([7u8; 32]);
        self.funding.set(vec![FundingUtxo {
            outpoint: OutPointRef {
                txid: funding_txid,
                vout: 0,
            },
            txout: TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: descriptor.at_derivation_index(0).unwrap().script_pubkey(),
            },
            derivation_index: 0,
        }]);
        let destination = descriptor.at_derivation_index(5).unwrap().script_pubkey();
        let spec = SpendSpec {
            inputs: vec![OutPointRef {
                txid: funding_txid,
                vout: 0,
            }],
            outputs: vec![SpendOutput {
                address: bitcoin::Address::from_script(&destination, NETWORK)
                    .unwrap()
                    .to_string()
                    .parse()
                    .unwrap(),
                amount_sats: 50_000,
            }],
            fee_sats: 500,
            change_output: Some(ChangeOutput {
                amount_sats: 49_500,
                derivation_index: 1,
            }),
        };

        let session = self
            .app
            .propose_spend(wallet.id, self.participants[0], spec)
            .await
            .unwrap();
        assert_eq!(session.status(), PsbtSessionStatus::Pending);

        // the spawned PSBT-creation job runs on the executor
        let session = self
            .wait_for_session_status(session.id, PsbtSessionStatus::Collecting)
            .await;
        (session, wallet)
    }

    async fn wait_for_session_status(
        &self,
        session_id: PsbtSessionId,
        expected: PsbtSessionStatus,
    ) -> PsbtSession {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let session = self.app.find_session(session_id).await.unwrap();
            if session.status() == expected {
                return session;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for session status {expected}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn signed_psbt(&self, signer_index: usize, unsigned: &bitcoin::Psbt) -> bitcoin::Psbt {
        let mut signed = unsigned.clone();
        signed
            .sign(&self.xprivs[signer_index], &Secp256k1::new())
            .map_err(|(_, errors)| errors)
            .unwrap();
        signed
    }
}

#[tokio::test]
async fn full_spend_flow_through_use_cases() -> anyhow::Result<()> {
    let Some(fixture) = Fixture::new().await else {
        return Ok(());
    };
    let (session, _wallet) = fixture.collecting_session().await;

    // signers fetch the unsigned PSBT (digest-verified) and sign on-device
    let unsigned = parse_psbt(&fixture.app.unsigned_psbt(session.id).await?)?;

    let mut session = session;
    for i in 0..2 {
        let signed = fixture.signed_psbt(i, &unsigned);
        session = fixture
            .app
            .submit_signed_psbt(session.id, fixture.participants[i], &signed.serialize())
            .await?;
    }
    assert!(session.threshold_met());
    assert_eq!(session.signature_count(), 2);

    // idempotent re-upload by the same signer
    let signed = fixture.signed_psbt(0, &unsigned);
    let after = fixture
        .app
        .submit_signed_psbt(session.id, fixture.participants[0], &signed.serialize())
        .await?;
    assert_eq!(after.signature_count(), 2);

    // the finalization job (spawned at every upload) recomputes the
    // final tx once quorum is met
    let session = fixture
        .wait_for_session_status(session.id, PsbtSessionStatus::Finalized)
        .await;
    let finalization = session.finalization().unwrap().clone();
    assert_eq!(finalization.sigs_used.len(), 2);

    // the final transaction is stored content-addressed and matches
    let final_bytes = fixture
        .blobs
        .get(&finalization.final_tx_hash)
        .await
        .unwrap();
    let final_tx: Transaction = consensus::deserialize(&final_bytes)?;
    assert_eq!(final_tx.compute_txid(), finalization.txid);
    // 2-of-3 witness: [dummy, sig, sig, witness_script]
    assert_eq!(final_tx.input[0].witness.len(), 4);

    fixture.jobs.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn keystore_submission_is_idempotent_through_use_cases() -> anyhow::Result<()> {
    let Some(fixture) = Fixture::new().await else {
        return Ok(());
    };
    let wallet = fixture
        .app
        .register_wallet(2, fixture.participants.clone())
        .await?;

    fixture
        .app
        .submit_keystore(
            wallet.id,
            fixture.participants[0],
            fixture.keystores[0].clone(),
        )
        .await?;
    // crash/retry: same participant, same key — no error, no new event
    let wallet = fixture
        .app
        .submit_keystore(
            wallet.id,
            fixture.participants[0],
            fixture.keystores[0].clone(),
        )
        .await?;
    assert_eq!(wallet.keystores().len(), 1);

    // a different key from the same participant is rejected...
    let (other_key, _) = make_keystore(&[9u8; 32]);
    let result = fixture
        .app
        .submit_keystore(wallet.id, fixture.participants[0], other_key.clone())
        .await;
    assert!(matches!(
        result,
        Err(CoordinationError::Wallet(
            WalletError::ParticipantAlreadySubmitted(_)
        ))
    ));

    // ...until it is explicitly removed
    fixture
        .app
        .remove_keystore(wallet.id, fixture.participants[0], fixture.participants[0])
        .await?;
    let wallet = fixture
        .app
        .submit_keystore(wallet.id, fixture.participants[0], other_key)
        .await?;
    assert_eq!(wallet.keystores().len(), 1);

    fixture.jobs.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn importing_same_wallet_twice_is_idempotent_find() -> anyhow::Result<()> {
    let Some(fixture) = Fixture::new().await else {
        return Ok(());
    };
    let original = fixture.active_wallet().await;

    // a second registration with the same policy; submitting the same
    // keys converges on the same descriptor — and fingerprint
    let duplicate = fixture
        .app
        .register_wallet(2, fixture.participants.clone())
        .await?;
    assert_ne!(duplicate.id, original.id);
    let mut resolved = duplicate;
    for i in 0..3 {
        resolved = fixture
            .app
            .submit_keystore(
                resolved.id,
                fixture.participants[i],
                fixture.keystores[i].clone(),
            )
            .await?;
    }
    // the activating submission collided on UNIQUE fingerprint and the
    // use-case layer resolved it to the existing wallet
    assert_eq!(resolved.id, original.id);
    assert_eq!(resolved.status(), WalletStatus::Active);

    // direct lookup by content address works too
    let fingerprint = original.descriptor_fingerprint().unwrap();
    let found = fixture
        .app
        .maybe_find_wallet_by_descriptor_fingerprint(fingerprint)
        .await?;
    assert_eq!(found.unwrap().id, original.id);

    fixture.jobs.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn propose_and_sign_are_gated_through_use_cases() -> anyhow::Result<()> {
    let Some(fixture) = Fixture::new().await else {
        return Ok(());
    };

    // propose on a wallet still collecting keystores
    let wallet = fixture
        .app
        .register_wallet(2, fixture.participants.clone())
        .await?;
    fixture
        .app
        .submit_keystore(
            wallet.id,
            fixture.participants[0],
            fixture.keystores[0].clone(),
        )
        .await?;
    let spec = SpendSpec {
        inputs: vec![OutPointRef {
            txid: bitcoin::Txid::from_byte_array([7u8; 32]),
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
    };
    let result = fixture
        .app
        .propose_spend(wallet.id, fixture.participants[0], spec)
        .await;
    assert!(matches!(
        result,
        Err(CoordinationError::PsbtSession(
            PsbtSessionError::WalletNotActive {
                status: WalletStatus::CollectingKeystores,
                ..
            }
        ))
    ));

    // a non-participant cannot submit a signature: the platform binds
    // the signer from the wallet's submissions, not client input
    let (session, _) = fixture.collecting_session().await;
    let unsigned = parse_psbt(&fixture.app.unsigned_psbt(session.id).await?)?;
    let signed = fixture.signed_psbt(0, &unsigned);
    let result = fixture
        .app
        .submit_signed_psbt(session.id, UserId::new(), &signed.serialize())
        .await;
    assert!(matches!(
        result,
        Err(CoordinationError::SignerNotBound { .. })
    ));

    fixture.jobs.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn cancel_wallet_through_use_cases() -> anyhow::Result<()> {
    let Some(fixture) = Fixture::new().await else {
        return Ok(());
    };
    let wallet = fixture
        .app
        .register_wallet(2, fixture.participants.clone())
        .await?;
    fixture
        .app
        .submit_keystore(
            wallet.id,
            fixture.participants[0],
            fixture.keystores[0].clone(),
        )
        .await?;

    let wallet = fixture
        .app
        .cancel_wallet(
            wallet.id,
            fixture.participants[0],
            "quorum fell apart".to_string(),
        )
        .await?;
    assert_eq!(wallet.status(), WalletStatus::Cancelled);

    // idempotent re-cancel
    let wallet = fixture
        .app
        .cancel_wallet(wallet.id, fixture.participants[0], "retry".to_string())
        .await?;
    assert_eq!(wallet.status(), WalletStatus::Cancelled);

    fixture.jobs.shutdown().await?;
    Ok(())
}
