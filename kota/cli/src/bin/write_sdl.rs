//! Print the GraphQL SDL of the kota schema to stdout (lana's
//! `write_sdl` codegen binary). No database needed — the schema is
//! built without an app.
//!
//! Regenerate the checked-in schema with:
//!
//! ```sh
//! cargo run -p kota-cli --bin write_sdl > kota/server/src/graphql/schema.graphql
//! ```

fn main() {
    println!("{}", kota_server::graphql::sdl());
}
