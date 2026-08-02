//! End-to-end cryptographic test of the full signing flow:
//!
//!   propose (Initialized with SpendSpec)
//!   -> async creation job builds + stores the unsigned PSBT (PsbtCreated)
//!   -> signer fetches by hash, verifies integrity, signs with a real key
//!   -> platform validates the submission is additive-only
//!   -> finalize at threshold, extract the final transaction
//!   -> the witness signature verifies cryptographically against the
//!      funding script's pubkey
//!
//! One dummy user, a 1-of-1 sortedmulti wallet (single keystore).

use core_coordination::{
    primitives::*,
    psbt::{parse_psbt, validate_signed_submission},
    psbt_session::{
        ChangeOutput, NewPsbtSession, OutPointRef, Policy, PsbtSession, PsbtSessionStatus,
        SpendOutput, SpendSpec,
    },
    storage::{BlobStore, InMemoryBlobStore},
    wallet::{
        FundingUtxo, build_unsigned_psbt, descriptor_fingerprints, sortedmulti_wsh_descriptor,
    },
};

use bitcoin::bip32::{DerivationPath, Fingerprint as KeyFingerprint, Xpriv, Xpub};
use bitcoin::ecdsa::Signature as EcdsaSignature;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{self, Message, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{Amount, Network, TxOut};
use chrono::{DateTime, Utc};
use es_entity::{IntoEvents, TryFromEvents};
use miniscript::descriptor::{Descriptor, DescriptorPublicKey, DescriptorXKey, Wildcard};
use std::str::FromStr;

const NETWORK: Network = Network::Regtest;

/// m/48'/0'/0'/2' — standard segwit multisig account path (BIP-48).
const ACCOUNT_PATH: &str = "m/48'/0'/0'/2'";

fn setup_wallet() -> (
    Secp256k1<secp256k1::All>,
    Xpriv,
    Descriptor<DescriptorPublicKey>,
    KeyFingerprint,
) {
    let secp = Secp256k1::new();
    let xpriv = Xpriv::new_master(NETWORK, &[42u8; 64]).unwrap();
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
    let descriptor = sortedmulti_wsh_descriptor(1, vec![keystore]).unwrap();

    (secp, xpriv, descriptor, master_fingerprint)
}

fn expires_at() -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(2_000_000_000, 0).unwrap()
}

struct Fixture {
    secp: Secp256k1<secp256k1::All>,
    xpriv: Xpriv,
    descriptor: Descriptor<DescriptorPublicKey>,
    fingerprint: KeyFingerprint,
    funding: Vec<FundingUtxo>,
    spec: SpendSpec,
}

impl Fixture {
    fn new() -> Self {
        let (secp, xpriv, descriptor, fingerprint) = setup_wallet();

        // wallet UTXO at derivation index 0 (receive chain)
        let funding_script = descriptor.at_derivation_index(0).unwrap().script_pubkey();
        let funding_txid = bitcoin::Txid::from_byte_array([7u8; 32]);
        let funding = vec![FundingUtxo {
            outpoint: OutPointRef {
                txid: funding_txid,
                vout: 0,
            },
            txout: TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: funding_script,
            },
            derivation_index: 0,
        }];

        // destination (wallet-derived here; external in a real spend —
        // the tx is valid either way). Change is not an address: the
        // creation job derives it from the descriptor at the given index.
        let destination = descriptor.at_derivation_index(5).unwrap().script_pubkey();

        let spec = SpendSpec {
            inputs: vec![OutPointRef {
                txid: funding_txid,
                vout: 0,
            }],
            outputs: vec![SpendOutput {
                address: bitcoin::Address::from_script(&destination, NETWORK)
                    .unwrap()
                    .to_string(),
                amount_sats: 50_000,
            }],
            fee_sats: 500,
            change_output: Some(ChangeOutput {
                amount_sats: 49_500,
                derivation_index: 1,
            }),
        };

        Self {
            secp,
            xpriv,
            descriptor,
            fingerprint,
            funding,
            spec,
        }
    }

    fn propose(&self) -> PsbtSession {
        let new_session = NewPsbtSession::try_new(
            PsbtSessionId::new(),
            WalletId::new(),
            UserId::new(),
            self.spec.clone(),
            Policy {
                threshold: 1,
                keystores: vec![self.fingerprint],
            },
            expires_at(),
        )
        .unwrap();
        PsbtSession::try_from_events(new_session.into_events()).unwrap()
    }
}

#[tokio::test]
async fn e2e_propose_create_sign_finalize() {
    let fixture = Fixture::new();
    let store = InMemoryBlobStore::default();

    // sanity: the descriptor's keystore matches the session policy
    assert_eq!(
        descriptor_fingerprints(&fixture.descriptor),
        vec![fixture.fingerprint]
    );

    // --- 1. propose (sync, cheap) ---
    let mut session = fixture.propose();
    assert_eq!(session.status(), PsbtSessionStatus::Pending);

    // --- 2. async creation job: build PSBT, upload, record hash ---
    let unsigned_psbt = build_unsigned_psbt(
        &fixture.spec,
        &fixture.descriptor,
        &fixture.funding,
        NETWORK,
    )
    .unwrap();
    let unsigned_hash = store.put(&unsigned_psbt.serialize()).await;
    assert!(
        session
            .record_psbt_created(unsigned_hash)
            .unwrap()
            .did_execute()
    );
    assert_eq!(session.status(), PsbtSessionStatus::Collecting);
    assert_eq!(session.unsigned_psbt_hash(), Some(unsigned_hash));

    // --- 3. signer: fetch by hash, verify integrity, sign on "device" ---
    let bytes = store.get(&unsigned_hash).await.unwrap();
    assert_eq!(
        PsbtHash::digest_of(&bytes),
        unsigned_hash,
        "content-addressed fetch is self-verifying"
    );
    let mut signed_psbt = parse_psbt(&bytes).unwrap();
    let original = signed_psbt.clone();

    // the PSBT carries everything a hardware wallet needs
    assert!(signed_psbt.inputs[0].witness_utxo.is_some());
    assert!(signed_psbt.inputs[0].witness_script.is_some());
    assert!(
        signed_psbt.inputs[0]
            .bip32_derivation
            .values()
            .any(|(fp, _)| *fp == fixture.fingerprint)
    );

    // the change output is wallet-derived (index 1) and carries the
    // witness script + key sources a signing device needs to verify
    // it belongs to the same multisig
    let change_spk = fixture
        .descriptor
        .at_derivation_index(1)
        .unwrap()
        .script_pubkey();
    assert_eq!(signed_psbt.unsigned_tx.output[1].script_pubkey, change_spk);
    assert!(signed_psbt.outputs[1].witness_script.is_some());
    assert!(
        signed_psbt.outputs[1]
            .bip32_derivation
            .values()
            .any(|(fp, _)| *fp == fixture.fingerprint)
    );

    signed_psbt
        .sign(&fixture.xpriv, &fixture.secp)
        .map_err(|(_, errors)| errors)
        .unwrap();
    assert_eq!(signed_psbt.inputs[0].partial_sigs.len(), 1);

    // --- 4. platform validates the submission is additive-only ---
    let added = validate_signed_submission(&original, &signed_psbt).unwrap();
    assert_eq!(added, 1);
    let signed_hash = store.put(&signed_psbt.serialize()).await;
    assert!(
        session
            .add_signature(fixture.fingerprint, signed_hash)
            .unwrap()
            .did_execute()
    );
    assert!(session.threshold_met());

    // --- 5. finalize: platform combines, finalizes, extracts ---
    use miniscript::psbt::PsbtExt;
    let final_psbt = signed_psbt
        .finalize(&fixture.secp)
        .map_err(|(_, errors)| errors)
        .unwrap();
    let tx = final_psbt.extract_tx().unwrap();
    let final_tx_hash = PsbtHash::digest_of(&bitcoin::consensus::serialize(&tx));
    assert!(
        session
            .finalize(tx.compute_txid(), final_tx_hash, vec![fixture.fingerprint])
            .unwrap()
            .did_execute()
    );
    assert_eq!(session.status(), PsbtSessionStatus::Finalized);

    // --- 6. the final transaction is cryptographically valid ---
    // witness for 1-of-1 sortedmulti: [OP_0 (dummy), signature, witness_script]
    let witness = &tx.input[0].witness;
    assert_eq!(witness.len(), 3);
    let witness_items = witness.to_vec();

    let sig = EcdsaSignature::from_slice(&witness_items[1]).unwrap();
    assert_eq!(sig.sighash_type, EcdsaSighashType::All);
    let witness_script = bitcoin::Script::from_bytes(&witness_items[2]);

    let sighash = SighashCache::new(&tx)
        .p2wsh_signature_hash(
            0,
            witness_script,
            Amount::from_sat(100_000),
            EcdsaSighashType::All,
        )
        .unwrap();

    // the pubkey the signature must verify against: the single key of the
    // 1-of-1 multisig at funding derivation index 0
    let account_path = DerivationPath::from_str(ACCOUNT_PATH).unwrap();
    let account_xpriv = fixture
        .xpriv
        .derive_priv(&fixture.secp, &account_path)
        .unwrap();
    let child_priv = account_xpriv
        .derive_priv(&fixture.secp, &DerivationPath::from_str("m/0/0").unwrap())
        .unwrap();
    let pubkey = child_priv.to_priv().public_key(&fixture.secp).inner;

    fixture
        .secp
        .verify_ecdsa(&Message::from(sighash), &sig.signature, &pubkey)
        .expect("witness signature must verify against the funding script pubkey");

    // outputs match the proposal
    let destination = fixture
        .descriptor
        .at_derivation_index(5)
        .unwrap()
        .script_pubkey();
    let change = fixture
        .descriptor
        .at_derivation_index(1)
        .unwrap()
        .script_pubkey();
    assert_eq!(tx.output[0].script_pubkey, destination);
    assert_eq!(tx.output[0].value, Amount::from_sat(50_000));
    assert_eq!(tx.output[1].script_pubkey, change);
    assert_eq!(tx.output[1].value, Amount::from_sat(49_500));
    // fee = inputs - outputs
    assert_eq!(
        fixture.funding[0].txout.value - tx.output[0].value - tx.output[1].value,
        Amount::from_sat(500)
    );
}

#[tokio::test]
async fn tampered_submission_is_rejected() {
    let fixture = Fixture::new();

    let unsigned_psbt = build_unsigned_psbt(
        &fixture.spec,
        &fixture.descriptor,
        &fixture.funding,
        NETWORK,
    )
    .unwrap();
    let mut tampered = unsigned_psbt.clone();
    tampered.unsigned_tx.output[0].value = Amount::from_sat(99_000);

    assert!(matches!(
        validate_signed_submission(&unsigned_psbt, &tampered),
        Err(core_coordination::psbt::PsbtValidationError::UnsignedTxModified)
    ));
}

#[tokio::test]
async fn removed_cosigner_signature_is_rejected() {
    let fixture = Fixture::new();

    let unsigned_psbt = build_unsigned_psbt(
        &fixture.spec,
        &fixture.descriptor,
        &fixture.funding,
        NETWORK,
    )
    .unwrap();

    // signer A signs
    let mut signed = unsigned_psbt.clone();
    signed
        .sign(&fixture.xpriv, &fixture.secp)
        .map_err(|(_, errors)| errors)
        .unwrap();

    // a second "signer" submits the signed PSBT but strips A's partial sig
    // and adds nothing — caught as a removal (and as no-new-signatures)
    let mut stripped = signed.clone();
    stripped.inputs[0].partial_sigs.clear();

    assert!(matches!(
        validate_signed_submission(&signed, &stripped),
        Err(core_coordination::psbt::PsbtValidationError::PartialSignatureRemoved(0))
    ));
}
