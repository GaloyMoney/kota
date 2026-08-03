//! Integration test for the jobs layer: the full session lifecycle
//! driven by job units against a real Postgres (skipped when
//! DATABASE_URL is unset, like the repo round-trip tests):
//!
//!   propose -> run_psbt_creation (Pending -> Collecting)
//!   -> signer signs + platform records the merged blob
//!   -> run_finalization (Collecting -> Finalized)
//!   -> apply_chain_observation: broadcast -> confirm -> reorg
//!      invalidation -> re-confirm
//!
//! Idempotent re-runs of each job are asserted throughout.

use core_coordination::jobs::{
    ChainObservation, FundingUtxoProvider, JobsError, apply_chain_observation, run_finalization,
    run_psbt_creation,
};
use core_coordination::primitives::*;
use core_coordination::psbt::{merge_partial_sigs, parse_psbt, validate_signed_submission};
use core_coordination::psbt_session::{
    ChangeOutput, NewPsbtSession, OutPointRef, PsbtSessionRepo, PsbtSessionStatus, SpendOutput,
    SpendSpec,
};
use core_coordination::storage::{BlobStore, InMemoryBlobStore};
use core_coordination::wallet::{
    FundingUtxo, NewWallet, Wallet, WalletRepo, descriptor_fingerprint, sortedmulti_wsh_descriptor,
};

use bitcoin::bip32::{DerivationPath, Fingerprint as KeyFingerprint, Xpriv, Xpub};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{self, Secp256k1};
use bitcoin::{Amount, Network, TxOut};
use chrono::{DateTime, Utc};
use es_entity::clock::ClockHandle;
use miniscript::descriptor::{Descriptor, DescriptorPublicKey, DescriptorXKey, Wildcard};
use std::str::FromStr;

const NETWORK: Network = Network::Regtest;
const ACCOUNT_PATH: &str = "m/48'/0'/0'/2'";

fn setup_wallet(
    seed: u8,
) -> (
    Secp256k1<secp256k1::All>,
    Xpriv,
    Descriptor<DescriptorPublicKey>,
    KeyFingerprint,
    DescriptorPublicKey,
) {
    let secp = Secp256k1::new();
    let xpriv = Xpriv::new_master(NETWORK, &[seed; 64]).unwrap();
    let master_fingerprint = xpriv.fingerprint(&secp);

    let account_path = DerivationPath::from_str(ACCOUNT_PATH).unwrap();
    let account_xpriv = xpriv.derive_priv(&secp, &account_path).unwrap();
    let account_xpub = Xpub::from_priv(&secp, &account_xpriv);

    let keystore = DescriptorPublicKey::XPub(DescriptorXKey {
        origin: Some((master_fingerprint, account_path)),
        xkey: account_xpub,
        derivation_path: DerivationPath::from_str("m/0").unwrap(),
        wildcard: Wildcard::Unhardened,
    });
    let descriptor = sortedmulti_wsh_descriptor(1, vec![keystore.clone()]).unwrap();

    (secp, xpriv, descriptor, master_fingerprint, keystore)
}

/// Chain-data double: serves the one funding UTXO the fixture spends.
struct StaticFunding {
    utxos: Vec<FundingUtxo>,
}

/// Wallet import is idempotent by design (descriptor fingerprint is a
/// content address, UNIQUE in the db) — re-registering returns the
/// existing row, which also keeps these tests re-runnable against the
/// same dev database. Otherwise the full lifecycle runs: policy
/// registration, keystore submission, activation.
async fn ensure_wallet(
    wallets: &WalletRepo,
    descriptor: &Descriptor<DescriptorPublicKey>,
    keystore: &DescriptorPublicKey,
) -> anyhow::Result<Wallet> {
    let fingerprint = descriptor_fingerprint(descriptor, NETWORK);
    if let Ok(wallet) = wallets
        .find_by_descriptor_fingerprint(Some(fingerprint))
        .await
    {
        return Ok(wallet);
    }
    let participant = UserId::new();
    let mut wallet = wallets
        .create(NewWallet::new(
            WalletId::new(),
            NETWORK,
            1,
            vec![participant],
        )?)
        .await?;
    let _ = wallet.add_keystore(keystore.clone(), participant)?;
    wallets.update(&mut wallet).await?;
    assert_eq!(wallet.descriptor(), Some(descriptor));
    Ok(wallet)
}

impl FundingUtxoProvider for StaticFunding {
    async fn funding_utxos(
        &self,
        _wallet: &Wallet,
        inputs: &[OutPointRef],
    ) -> Result<Vec<FundingUtxo>, JobsError> {
        Ok(self
            .utxos
            .iter()
            .filter(|u| inputs.contains(&u.outpoint))
            .cloned()
            .collect())
    }
}

#[tokio::test]
async fn jobs_drive_full_lifecycle() -> anyhow::Result<()> {
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL not set, skipping");
        return Ok(());
    };
    let pool = sqlx::PgPool::connect(&database_url).await?;
    let (clock, _ctrl) = ClockHandle::manual();
    let sessions = PsbtSessionRepo::new(&pool, clock.clone());
    let wallets = WalletRepo::new(&pool, clock);
    let blobs = InMemoryBlobStore::default();

    let (secp, xpriv, descriptor, fingerprint, keystore) = setup_wallet(7);

    // register the wallet (policy + keystore -> Active)
    let wallet = ensure_wallet(&wallets, &descriptor, &keystore).await?;

    // one funding UTXO at derivation index 0
    let funding_txid = bitcoin::Txid::from_byte_array([42u8; 32]);
    let funding = vec![FundingUtxo {
        outpoint: OutPointRef {
            txid: funding_txid,
            vout: 0,
        },
        txout: TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: descriptor.at_derivation_index(0).unwrap().script_pubkey(),
        },
        derivation_index: 0,
    }];
    let provider = StaticFunding {
        utxos: funding.clone(),
    };

    // propose a spend
    let destination = descriptor.at_derivation_index(5).unwrap().script_pubkey();
    let spec = SpendSpec {
        inputs: vec![funding[0].outpoint.clone()],
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
    let session = sessions
        .create(NewPsbtSession::try_new(
            PsbtSessionId::new(),
            &wallet,
            UserId::new(),
            spec,
            DateTime::<Utc>::from_timestamp(1_900_604_800, 0).unwrap(),
            DateTime::<Utc>::from_timestamp(1_900_000_000, 0).unwrap(),
        )?)
        .await?;
    let session_id = session.id;

    // finalization before the threshold is a clean, retryable refusal
    assert!(matches!(
        run_finalization(&sessions, &blobs, session_id).await,
        Err(JobsError::UnexpectedStatus { .. })
    ));

    // --- PSBT-creation job ---
    let unsigned_hash =
        run_psbt_creation(&sessions, &wallets, &blobs, &provider, NETWORK, session_id).await?;
    let unsigned_bytes = blobs.get(&unsigned_hash).await.expect("blob stored");
    let unsigned = parse_psbt(&unsigned_bytes)?;
    let session = sessions.find_by_id(session_id).await?;
    assert_eq!(session.status(), PsbtSessionStatus::Collecting);

    // idempotent re-run: same content address, no extra events
    let rerun =
        run_psbt_creation(&sessions, &wallets, &blobs, &provider, NETWORK, session_id).await?;
    assert_eq!(rerun, unsigned_hash);

    // --- signer flow (same as the use-case layer would do) ---
    let mut signed = unsigned.clone();
    signed.sign(&xpriv, &secp).map_err(|(_, e)| e).unwrap();
    let extracted = validate_signed_submission(&unsigned, &signed, &fingerprint)?;
    let merged = merge_partial_sigs(&unsigned, &extracted);
    let merged_hash = blobs.put(&merged.serialize()).await;
    let mut session = sessions.find_by_id(session_id).await?;
    let _ = session.add_signature(fingerprint, merged_hash, chrono::Utc::now())?;
    sessions.update(&mut session).await?;

    // --- finalization job ---
    let txid = run_finalization(&sessions, &blobs, session_id).await?;
    let session = sessions.find_by_id(session_id).await?;
    assert_eq!(session.status(), PsbtSessionStatus::Finalized);
    let finalization = session.finalization().unwrap();
    assert_eq!(finalization.txid, txid);
    assert_eq!(finalization.sigs_used, vec![fingerprint]);

    // the recorded txid is the txid of the recorded final-tx blob
    let final_bytes = blobs.get(&finalization.final_tx_hash).await.unwrap();
    let final_tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&final_bytes)?;
    assert_eq!(final_tx.compute_txid(), txid);

    // idempotent re-run
    assert_eq!(run_finalization(&sessions, &blobs, session_id).await?, txid);

    // --- chain-sync job ---
    let block_hash = bitcoin::BlockHash::from_byte_array([1u8; 32]);
    apply_chain_observation(&sessions, session_id, ChainObservation::Broadcast { txid }).await?;
    let session = sessions.find_by_id(session_id).await?;
    assert_eq!(session.status(), PsbtSessionStatus::Broadcast);

    apply_chain_observation(
        &sessions,
        session_id,
        ChainObservation::Confirmed {
            txid,
            height: 800_000,
            block_hash,
        },
    )
    .await?;
    let session = sessions.find_by_id(session_id).await?;
    assert_eq!(session.status(), PsbtSessionStatus::Confirmed);

    // a reorg unwinds it; a re-confirmation in the new chain re-executes
    apply_chain_observation(
        &sessions,
        session_id,
        ChainObservation::Invalidated {
            reason: core_coordination::psbt_session::InvalidationReason::Reorged,
        },
    )
    .await?;
    let session = sessions.find_by_id(session_id).await?;
    assert_eq!(session.status(), PsbtSessionStatus::Invalidated);

    apply_chain_observation(
        &sessions,
        session_id,
        ChainObservation::Confirmed {
            txid,
            height: 800_001,
            block_hash: bitcoin::BlockHash::from_byte_array([2u8; 32]),
        },
    )
    .await?;
    let session = sessions.find_by_id(session_id).await?;
    assert_eq!(session.status(), PsbtSessionStatus::Confirmed);

    // an observation about a different txid can never attach to the session
    let wrong_txid = bitcoin::Txid::from_byte_array([9u8; 32]);
    assert!(matches!(
        apply_chain_observation(
            &sessions,
            session_id,
            ChainObservation::Broadcast { txid: wrong_txid }
        )
        .await,
        Err(JobsError::Session(
            core_coordination::psbt_session::PsbtSessionError::TxidMismatch
        ))
    ));

    Ok(())
}

/// The same lifecycle, but driven through the actual `job` executor:
/// spawn -> poll -> await_completion, exactly as production wiring does.
#[tokio::test]
async fn executor_drives_creation_and_finalization() -> anyhow::Result<()> {
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL not set, skipping");
        return Ok(());
    };
    let pool = sqlx::PgPool::connect(&database_url).await?;
    let (clock, _ctrl) = ClockHandle::manual();
    let sessions = PsbtSessionRepo::new(&pool, clock.clone());
    let wallets = WalletRepo::new(&pool, clock.clone());
    let blobs = std::sync::Arc::new(InMemoryBlobStore::default());

    let (secp, xpriv, descriptor, fingerprint, keystore) = setup_wallet(8);
    let wallet = ensure_wallet(&wallets, &descriptor, &keystore).await?;

    let funding_txid = bitcoin::Txid::from_byte_array([43u8; 32]);
    let funding = vec![FundingUtxo {
        outpoint: OutPointRef {
            txid: funding_txid,
            vout: 0,
        },
        txout: TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: descriptor.at_derivation_index(0).unwrap().script_pubkey(),
        },
        derivation_index: 0,
    }];
    let provider = StaticFunding {
        utxos: funding.clone(),
    };

    let destination = descriptor.at_derivation_index(5).unwrap().script_pubkey();
    let session = sessions
        .create(NewPsbtSession::try_new(
            PsbtSessionId::new(),
            &wallet,
            UserId::new(),
            SpendSpec {
                inputs: vec![funding[0].outpoint.clone()],
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
            },
            DateTime::<Utc>::from_timestamp(1_900_604_800, 0).unwrap(),
            DateTime::<Utc>::from_timestamp(1_900_000_000, 0).unwrap(),
        )?)
        .await?;
    let session_id = session.id;

    // register initializers and start the executor — the production wiring
    let mut jobs = job::Jobs::init(
        job::JobSvcConfig::builder()
            .pool(pool.clone())
            .clock(clock.clone())
            .build()
            .unwrap(),
    )
    .await?;
    let spawners = core_coordination::jobs::register(
        &mut jobs,
        &sessions,
        &wallets,
        blobs.clone(),
        std::sync::Arc::new(provider),
        NETWORK,
    );
    jobs.start_poll().await?;

    // spawn PSBT creation; the executor runs it to completion
    let creation_id = job::JobId::new();
    spawners
        .psbt_creation
        .spawn(
            creation_id,
            core_coordination::jobs::PsbtCreationJobConfig { session_id },
        )
        .await?;
    jobs.await_completion(creation_id, Some(std::time::Duration::from_secs(30)))
        .await?;
    let session = sessions.find_by_id(session_id).await?;
    assert_eq!(session.status(), PsbtSessionStatus::Collecting);

    // signer signs; platform validates, rebuilds, stores, records
    let unsigned_hash = session.unsigned_psbt_hash().unwrap();
    let unsigned = parse_psbt(&blobs.get(&unsigned_hash).await.unwrap())?;
    let mut signed = unsigned.clone();
    signed.sign(&xpriv, &secp).map_err(|(_, e)| e).unwrap();
    let extracted = validate_signed_submission(&unsigned, &signed, &fingerprint)?;
    let merged = merge_partial_sigs(&unsigned, &extracted);
    let merged_hash = blobs.put(&merged.serialize()).await;
    let mut session = sessions.find_by_id(session_id).await?;
    let _ = session.add_signature(fingerprint, merged_hash, chrono::Utc::now())?;
    sessions.update(&mut session).await?;

    // spawn finalization; the executor runs it to completion
    let finalization_id = job::JobId::new();
    spawners
        .finalization
        .spawn(
            finalization_id,
            core_coordination::jobs::FinalizationJobConfig { session_id },
        )
        .await?;
    jobs.await_completion(finalization_id, Some(std::time::Duration::from_secs(30)))
        .await?;
    let session = sessions.find_by_id(session_id).await?;
    assert_eq!(session.status(), PsbtSessionStatus::Finalized);
    assert_eq!(session.finalization().unwrap().sigs_used, vec![fingerprint]);

    jobs.shutdown().await?;
    Ok(())
}

/// A session cancelled after a job was spawned must not poison the
/// retry queue: both jobs complete as no-ops.
#[tokio::test]
async fn jobs_for_ended_session_complete_as_noops() -> anyhow::Result<()> {
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL not set, skipping");
        return Ok(());
    };
    let pool = sqlx::PgPool::connect(&database_url).await?;
    let (clock, _ctrl) = ClockHandle::manual();
    let sessions = PsbtSessionRepo::new(&pool, clock.clone());
    let wallets = WalletRepo::new(&pool, clock.clone());
    let blobs = std::sync::Arc::new(InMemoryBlobStore::default());

    let (_, _, descriptor, _, keystore) = setup_wallet(9);
    let wallet = ensure_wallet(&wallets, &descriptor, &keystore).await?;

    let funding_txid = bitcoin::Txid::from_byte_array([44u8; 32]);
    let destination = descriptor.at_derivation_index(5).unwrap().script_pubkey();
    let session = sessions
        .create(NewPsbtSession::try_new(
            PsbtSessionId::new(),
            &wallet,
            UserId::new(),
            SpendSpec {
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
                change_output: None,
            },
            DateTime::<Utc>::from_timestamp(1_900_604_800, 0).unwrap(),
            DateTime::<Utc>::from_timestamp(1_900_000_000, 0).unwrap(),
        )?)
        .await?;
    let session_id = session.id;

    // the session is cancelled before any job runs
    let mut session = sessions.find_by_id(session_id).await?;
    let _ = session.cancel(UserId::new(), "no longer needed".to_string())?;
    sessions.update(&mut session).await?;

    let mut jobs = job::Jobs::init(
        job::JobSvcConfig::builder()
            .pool(pool.clone())
            .clock(clock.clone())
            .build()
            .unwrap(),
    )
    .await?;
    let spawners = core_coordination::jobs::register(
        &mut jobs,
        &sessions,
        &wallets,
        blobs.clone(),
        std::sync::Arc::new(StaticFunding { utxos: vec![] }),
        NETWORK,
    );
    jobs.start_poll().await?;

    let creation_id = job::JobId::new();
    spawners
        .psbt_creation
        .spawn(
            creation_id,
            core_coordination::jobs::PsbtCreationJobConfig { session_id },
        )
        .await?;
    jobs.await_completion(creation_id, Some(std::time::Duration::from_secs(30)))
        .await?;

    let finalization_id = job::JobId::new();
    spawners
        .finalization
        .spawn(
            finalization_id,
            core_coordination::jobs::FinalizationJobConfig { session_id },
        )
        .await?;
    jobs.await_completion(finalization_id, Some(std::time::Duration::from_secs(30)))
        .await?;

    let session = sessions.find_by_id(session_id).await?;
    assert_eq!(session.status(), PsbtSessionStatus::Cancelled);

    jobs.shutdown().await?;
    Ok(())
}
