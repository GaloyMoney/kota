use es_entity::clock::ClockHandle;
use sqlx::PgPool;

use es_entity::*;

use crate::primitives::{DescriptorFingerprint, WalletId};

use super::entity::*;
use super::primitives::WalletStatus;

#[derive(EsRepo)]
#[es_repo(
    entity = "Wallet",
    columns(
        status(
            ty = "WalletStatus",
            list_for,
            create(accessor = "status()"),
            update(accessor = "status()")
        ),
        descriptor_fingerprint(
            ty = "Option<DescriptorFingerprint>",
            create(accessor = "descriptor_fingerprint()"),
            update(accessor = "descriptor_fingerprint()")
        )
    ),
    tbl_prefix = "core"
)]
pub struct WalletRepo {
    pool: PgPool,
    clock: ClockHandle,
}

impl Clone for WalletRepo {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
            clock: self.clock.clone(),
        }
    }
}

impl WalletRepo {
    pub fn new(pool: &PgPool, clock: ClockHandle) -> Self {
        Self {
            pool: pool.clone(),
            clock,
        }
    }
}

mod wallet_status_sqlx {
    use sqlx::{Type, postgres::*};

    use super::WalletStatus;

    impl Type<Postgres> for WalletStatus {
        fn type_info() -> PgTypeInfo {
            <String as Type<Postgres>>::type_info()
        }

        fn compatible(ty: &PgTypeInfo) -> bool {
            <String as Type<Postgres>>::compatible(ty)
        }
    }

    impl sqlx::Encode<'_, Postgres> for WalletStatus {
        fn encode_by_ref(
            &self,
            buf: &mut PgArgumentBuffer,
        ) -> Result<sqlx::encode::IsNull, Box<dyn std::error::Error + Sync + Send>> {
            <String as sqlx::Encode<'_, Postgres>>::encode(self.to_string(), buf)
        }
    }

    impl<'r> sqlx::Decode<'r, Postgres> for WalletStatus {
        fn decode(value: PgValueRef<'r>) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
            let s = <String as sqlx::Decode<Postgres>>::decode(value)?;
            Ok(s.parse().map_err(|e: strum::ParseError| Box::new(e))?)
        }
    }

    impl PgHasArrayType for WalletStatus {
        fn array_type_info() -> PgTypeInfo {
            <String as sqlx::postgres::PgHasArrayType>::array_type_info()
        }
    }
}

mod descriptor_fingerprint_sqlx {
    use sqlx::{Type, postgres::*};

    use super::DescriptorFingerprint;

    impl Type<Postgres> for DescriptorFingerprint {
        fn type_info() -> PgTypeInfo {
            <String as Type<Postgres>>::type_info()
        }

        fn compatible(ty: &PgTypeInfo) -> bool {
            <String as Type<Postgres>>::compatible(ty)
        }
    }

    impl sqlx::Encode<'_, Postgres> for DescriptorFingerprint {
        fn encode_by_ref(
            &self,
            buf: &mut PgArgumentBuffer,
        ) -> Result<sqlx::encode::IsNull, Box<dyn std::error::Error + Sync + Send>> {
            <String as sqlx::Encode<'_, Postgres>>::encode(self.to_string(), buf)
        }
    }

    impl<'r> sqlx::Decode<'r, Postgres> for DescriptorFingerprint {
        fn decode(value: PgValueRef<'r>) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
            let s = <String as sqlx::Decode<Postgres>>::decode(value)?;
            Ok(s.parse()?)
        }
    }

    impl PgHasArrayType for DescriptorFingerprint {
        fn array_type_info() -> PgTypeInfo {
            <String as sqlx::postgres::PgHasArrayType>::array_type_info()
        }
    }
}
