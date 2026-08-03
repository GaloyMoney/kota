use async_graphql::*;

use core_coordination::primitives::DescriptorFingerprint;
use miniscript::descriptor::DescriptorPublicKey;

use super::{psbt_session::*, wallet::*};
use crate::app_and_sub_from_ctx;
use crate::primitives::*;

pub struct Query;

#[Object]
impl Query {
    async fn wallet(
        &self,
        ctx: &Context<'_>,
        id: WalletId,
    ) -> async_graphql::Result<Option<Wallet>> {
        let (app, _) = app_and_sub_from_ctx!(ctx);
        Ok(app.maybe_find_wallet(id).await?.map(Wallet::from))
    }

    /// Idempotent wallet import: look up a wallet by its content
    /// address (network + canonical descriptor).
    async fn wallet_by_descriptor_fingerprint(
        &self,
        ctx: &Context<'_>,
        fingerprint: String,
    ) -> async_graphql::Result<Option<Wallet>> {
        let (app, _) = app_and_sub_from_ctx!(ctx);
        let fingerprint: DescriptorFingerprint = fingerprint
            .parse()
            .map_err(|e| Error::new(format!("invalid descriptor fingerprint: {e}")))?;
        Ok(app
            .maybe_find_wallet_by_descriptor_fingerprint(fingerprint)
            .await?
            .map(Wallet::from))
    }

    async fn psbt_session(
        &self,
        ctx: &Context<'_>,
        id: PsbtSessionId,
    ) -> async_graphql::Result<Option<PsbtSession>> {
        let (app, _) = app_and_sub_from_ctx!(ctx);
        Ok(app.maybe_find_session(id).await?.map(PsbtSession::from))
    }
}

pub struct Mutation;

#[Object]
impl Mutation {
    /// Register a wallet policy: an N-of-M multisig expecting one
    /// keystore from each participant.
    async fn wallet_register(
        &self,
        ctx: &Context<'_>,
        input: WalletRegisterInput,
    ) -> async_graphql::Result<WalletRegisterPayload> {
        let (app, _) = app_and_sub_from_ctx!(ctx);
        Ok(app
            .register_wallet(input.threshold, input.participants)
            .await?
            .into())
    }

    /// Submit the acting user's keystore. Activates the wallet when
    /// the quorum completes; colliding with an existing wallet's
    /// descriptor fingerprint resolves to that wallet (idempotent
    /// import).
    async fn wallet_keystore_submit(
        &self,
        ctx: &Context<'_>,
        input: WalletKeystoreSubmitInput,
    ) -> async_graphql::Result<WalletKeystoreSubmitPayload> {
        let (app, sub) = app_and_sub_from_ctx!(ctx);
        let keystore: DescriptorPublicKey = input
            .keystore
            .parse()
            .map_err(|e| Error::new(format!("invalid keystore: {e}")))?;
        Ok(app
            .submit_keystore(input.wallet_id, sub, keystore)
            .await?
            .into())
    }

    /// Withdraw a participant's keystore pre-activation so they can
    /// submit a replacement.
    async fn wallet_keystore_remove(
        &self,
        ctx: &Context<'_>,
        input: WalletKeystoreRemoveInput,
    ) -> async_graphql::Result<WalletKeystoreRemovePayload> {
        let (app, sub) = app_and_sub_from_ctx!(ctx);
        Ok(app
            .remove_keystore(input.wallet_id, input.participant, sub)
            .await?
            .into())
    }

    /// Abandon a wallet that is stuck collecting keystores.
    async fn wallet_cancel(
        &self,
        ctx: &Context<'_>,
        input: WalletCancelInput,
    ) -> async_graphql::Result<WalletCancelPayload> {
        let (app, sub) = app_and_sub_from_ctx!(ctx);
        Ok(app
            .cancel_wallet(input.wallet_id, sub, input.reason)
            .await?
            .into())
    }

    /// Propose a spend on an active wallet. The session starts
    /// `Pending`; the PSBT-creation job transitions it to
    /// `Collecting` asynchronously.
    async fn spend_propose(
        &self,
        ctx: &Context<'_>,
        input: SpendProposeInput,
    ) -> async_graphql::Result<SpendProposePayload> {
        let (app, sub) = app_and_sub_from_ctx!(ctx);
        let (wallet_id, spend) = input.into_wallet_and_spec()?;
        Ok(app.propose_spend(wallet_id, sub, spend).await?.into())
    }

    /// Submit the acting user's signed PSBT. The signer is bound from
    /// the wallet's recorded keystore submissions, never from client
    /// input.
    async fn signed_psbt_submit(
        &self,
        ctx: &Context<'_>,
        input: SignedPsbtSubmitInput,
    ) -> async_graphql::Result<SignedPsbtSubmitPayload> {
        let (app, sub) = app_and_sub_from_ctx!(ctx);
        Ok(app
            .submit_signed_psbt(input.session_id, sub, &input.signed_psbt.0)
            .await?
            .into())
    }
}
