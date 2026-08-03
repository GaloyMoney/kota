//! The kota API layer: an async-graphql/axum server over the
//! `Coordination` use-case service, following the lana `admin-server`
//! pattern at kota's current scale.
//!
//! - [`run`] serves `/health` and `/graphql` and owns the axum wiring;
//!   the GraphQL schema lives in [`graphql`], one module per domain
//!   (`wallet`, `psbt_session`) with the `Query`/`Mutation` roots in
//!   `graphql::schema`.
//! - The acting user arrives as an [`KotaAuthContext`], extracted from
//!   the `x-user-id` header in [`graphql_handler`]. This is a dev
//!   stand-in: lana resolves the subject from a JWT against keycloak,
//!   and kota will too once its user/auth crate lands — the app layer
//!   already treats the `UserId` as externally authenticated.
//! - The schema needs a *concrete* app type, so the blob store is
//!   type-erased behind [`DynBlobStore`]; the binary picks the backend.
//!
//! Lana patterns deliberately not adopted yet: dataloaders (no nested
//! entity resolution exists), JWT/JWKS auth (no user crate), SSE
//! subscriptions (no outbox).

mod blob_store;
mod config;
pub mod graphql;
mod primitives;

use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::{Extension, Router, http::HeaderMap, routing::get};
use tracing::{info, instrument};

use kota_app::Coordination;

pub use blob_store::DynBlobStore;
pub use config::*;
use primitives::*;

use std::future::Future;

/// The concrete application type the schema is built over.
pub type App = Coordination<DynBlobStore>;

#[instrument(name = "server.run", skip_all)]
pub async fn run<S>(config: ServerConfig, app: App, signal: S) -> anyhow::Result<()>
where
    S: Future<Output = ()> + Send + 'static,
{
    let port = config.port;
    let schema = graphql::schema(app);

    let app = Router::new()
        .route("/health", get(health_check))
        .route(
            "/graphql",
            get(health_check).post(axum::routing::post(graphql_handler)),
        )
        .layer(Extension(schema));

    info!("Starting kota server on port {port}");
    let listener =
        tokio::net::TcpListener::bind(&std::net::SocketAddr::from(([0, 0, 0, 0], port))).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(signal)
        .await?;
    Ok(())
}

#[instrument(
    name = "server.graphql",
    skip_all,
    fields(
        graphql.operation_name,
        graphql.operation_type,
        graphql.query,
        user.id,
    )
)]
pub async fn graphql_handler(
    schema: Extension<graphql::KotaSchema>,
    headers: HeaderMap,
    req: GraphQLRequest,
) -> GraphQLResponse {
    let mut req = req.into_inner();

    // Dev stand-in for upstream authentication (see module docs): the
    // caller's user id arrives as a header and is trusted as-is.
    let Some(user_id) = headers
        .get("x-user-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| uuid::Uuid::parse_str(value).ok())
    else {
        tracing::warn!("request missing a valid x-user-id header");
        return async_graphql::Response::from_errors(vec![async_graphql::ServerError::new(
            "Missing or invalid x-user-id header",
            None,
        )])
        .into();
    };

    tracing::Span::current().record("user.id", tracing::field::debug(&user_id));

    if let Some(op_name) = req.operation_name.as_ref() {
        tracing::Span::current().record("graphql.operation_name", op_name);
    }

    if let Some(query_type) = req.query.split_whitespace().next() {
        tracing::Span::current().record("graphql.operation_type", query_type);
    }

    req = req.data(KotaAuthContext {
        sub: UserId::from(user_id),
    });

    let query_text = req.query.clone();
    let response = schema.execute(req).await;
    if response.errors.iter().any(|err| err.path.is_empty()) {
        // Request-level failures (parse, validation) leave no parsed
        // document behind, so record the raw query here.
        tracing::Span::current().record("graphql.query", query_text.as_str());
    }
    if !response.errors.is_empty() {
        for err in &response.errors {
            tracing::warn!(
                path = ?err.path,
                locations = ?err.locations,
                extensions = ?err.extensions,
                "{}",
                err.message
            );
        }
    }
    response.into()
}

async fn health_check() -> &'static str {
    "OK"
}
