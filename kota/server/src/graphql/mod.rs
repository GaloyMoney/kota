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

pub fn schema(app: App) -> KotaSchema {
    Schema::build(Query, Mutation, EmptySubscription)
        .limit_depth(MAX_GRAPHQL_DEPTH)
        .limit_complexity(MAX_GRAPHQL_COMPLEXITY)
        .data(app)
        .finish()
}
