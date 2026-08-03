use es_entity::clock::ClockHandle;
use sqlx::PgPool;

use es_entity::*;

use crate::primitives::{PsbtSessionId, WalletId};

use super::entity::*;
use super::primitives::PsbtSessionStatus;

#[derive(EsRepo)]
#[es_repo(
    entity = "PsbtSession",
    columns(
        wallet_id(ty = "WalletId", create(accessor = "wallet_id()")),
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
