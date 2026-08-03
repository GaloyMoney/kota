use async_graphql::*;
use serde::{Deserialize, Serialize};

// The es-entity `graphql` feature (enabled in this crate's Cargo.toml)
// makes these `entity_id!` types their own GraphQL scalars.
pub use core_coordination::primitives::{PsbtSessionId, UserId, WalletId};

pub use std::sync::Arc;

/// The acting user for a request, extracted from the `x-user-id` header
/// (dev stand-in for upstream authentication — see crate docs). The app
/// layer enforces the signer ↔ keystore binding against this id.
#[derive(Debug, Clone)]
pub struct KotaAuthContext {
    pub sub: UserId,
}

/// Base64-encoded binary payload — PSBTs cross the API as files/QRs in
/// the real signer UX; base64 is the JSON-friendly carrier.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Base64(pub Vec<u8>);

#[Scalar]
impl ScalarType for Base64 {
    fn parse(value: Value) -> InputValueResult<Self> {
        use base64::Engine;
        if let Value::String(s) = &value {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(s)
                .map_err(|e| InputValueError::custom(format!("invalid base64: {e}")))?;
            Ok(Base64(bytes))
        } else {
            Err(InputValueError::expected_type(value))
        }
    }

    fn to_value(&self) -> Value {
        use base64::Engine;
        Value::String(base64::engine::general_purpose::STANDARD.encode(&self.0))
    }
}

impl From<Vec<u8>> for Base64 {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}
