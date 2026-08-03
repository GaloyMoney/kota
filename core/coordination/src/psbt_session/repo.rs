use es_entity::clock::ClockHandle;
use sqlx::PgPool;

use es_entity::*;

use crate::primitives::{PsbtSessionId, WalletId};

use super::entity::*;
use super::primitives::{OutPointRef, PsbtSessionStatus};

#[derive(EsRepo)]
#[es_repo(
    entity = "PsbtSession",
    columns(
        wallet_id(ty = "WalletId", list_for, create(accessor = "wallet_id()")),
        status(
            ty = "PsbtSessionStatus",
            list_for,
            create(accessor = "status()"),
            update(accessor = "status()")
        )
    ),
    tbl_prefix = "core"
)]
pub struct PsbtSessionRepo {
    pool: PgPool,
    clock: ClockHandle,
}

impl Clone for PsbtSessionRepo {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
            clock: self.clock.clone(),
        }
    }
}

impl PsbtSessionRepo {
    pub fn new(pool: &PgPool, clock: ClockHandle) -> Self {
        Self {
            pool: pool.clone(),
            clock,
        }
    }

    /// Outpoints from `inputs` that another *live* session of the same
    /// wallet already consumes — i.e. proposing `inputs` would race an
    /// existing session to broadcast. The use-case layer must call this
    /// before `NewPsbtSession::try_new` and reject on a non-empty
    /// result: two live proposals spending the same outpoint means one
    /// of them can never confirm.
    ///
    /// This is an advisory guard at proposal time, not a lock: two
    /// concurrent proposals can both pass it. The race remainder is
    /// resolved by chain sync — the loser's inputs are observed spent
    /// and the session is `Invalidated` with
    /// `InvalidationReason::InputsSpentExternally` (accepted from any
    /// pre-broadcast status for exactly this reason).
    pub async fn conflicting_inputs(
        &self,
        wallet_id: WalletId,
        inputs: &[OutPointRef],
    ) -> Result<Vec<OutPointRef>, PsbtSessionQueryError> {
        let mut conflicting: Vec<OutPointRef> = Vec::new();
        let mut args = es_entity::PaginatedQueryArgs::default();
        loop {
            let es_entity::PaginatedQueryRet {
                entities,
                has_next_page,
                end_cursor,
            } = self
                .list_for_wallet_id_by_id(wallet_id, args, es_entity::ListDirection::Descending)
                .await?;
            for session in entities {
                if !session.status().claims_inputs() {
                    continue;
                }
                for input in &session.inputs {
                    if inputs.contains(input) && !conflicting.contains(input) {
                        conflicting.push(input.clone());
                    }
                }
            }
            if !has_next_page {
                return Ok(conflicting);
            }
            args = es_entity::PaginatedQueryArgs {
                after: end_cursor,
                ..Default::default()
            };
        }
    }
}

mod psbt_session_status_sqlx {
    use sqlx::{Type, postgres::*};

    use super::PsbtSessionStatus;

    impl Type<Postgres> for PsbtSessionStatus {
        fn type_info() -> PgTypeInfo {
            <String as Type<Postgres>>::type_info()
        }

        fn compatible(ty: &PgTypeInfo) -> bool {
            <String as Type<Postgres>>::compatible(ty)
        }
    }

    impl sqlx::Encode<'_, Postgres> for PsbtSessionStatus {
        fn encode_by_ref(
            &self,
            buf: &mut PgArgumentBuffer,
        ) -> Result<sqlx::encode::IsNull, Box<dyn std::error::Error + Sync + Send>> {
            <String as sqlx::Encode<'_, Postgres>>::encode(self.to_string(), buf)
        }
    }

    impl<'r> sqlx::Decode<'r, Postgres> for PsbtSessionStatus {
        fn decode(value: PgValueRef<'r>) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
            let s = <String as sqlx::Decode<Postgres>>::decode(value)?;
            Ok(s.parse().map_err(|e: strum::ParseError| Box::new(e))?)
        }
    }

    impl PgHasArrayType for PsbtSessionStatus {
        fn array_type_info() -> PgTypeInfo {
            <String as sqlx::postgres::PgHasArrayType>::array_type_info()
        }
    }
}
