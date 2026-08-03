mod psbt_session;
mod schema;
mod wallet;
#[macro_use]
pub(crate) mod macros;

use async_graphql::*;

pub use schema::*;

use crate::App;

const MAX_GRAPHQL_DEPTH: usize = 15;
const MAX_GRAPHQL_COMPLEXITY: usize = 500;

pub type KotaSchema = Schema<Query, Mutation, EmptySubscription>;

/// Build the schema. `None` builds it without an app — resolvers
/// panic if executed, but SDL export (write_sdl, the freshness test
/// below) never executes them.
pub fn schema(app: Option<App>) -> KotaSchema {
    let mut builder = Schema::build(Query, Mutation, EmptySubscription)
        .limit_depth(MAX_GRAPHQL_DEPTH)
        .limit_complexity(MAX_GRAPHQL_COMPLEXITY);
    if let Some(app) = app {
        builder = builder.data(app);
    }
    builder.finish()
}

/// The SDL as it is checked in at `schema.graphql` — single source
/// for the export binary and the freshness test.
pub fn sdl() -> String {
    schema(None)
        .sdl_with_options(
            SDLExportOptions::new()
                .sorted_fields()
                .sorted_arguments()
                .sorted_enum_items(),
        )
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    /// The checked-in `schema.graphql` must never drift from the
    /// code-defined schema. Regenerate with:
    ///
    /// ```sh
    /// cargo run -p kota-cli --bin write_sdl > kota/server/src/graphql/schema.graphql
    /// ```
    #[test]
    fn checked_in_sdl_is_up_to_date() {
        let checked_in = include_str!("schema.graphql");
        assert_eq!(
            super::sdl(),
            checked_in.trim(),
            "schema.graphql is stale — regenerate with \
             `cargo run -p kota-cli --bin write_sdl > kota/server/src/graphql/schema.graphql`"
        );
    }
}
