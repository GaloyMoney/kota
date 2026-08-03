/// Helper to extract the 'app' and 'sub' args (lana's
/// `app_and_sub_from_ctx!`).
///
/// Instead of:
/// ```rust,ignore
/// async fn wallet(&self, ctx: &Context<'_>) -> async_graphql::Result<Option<Wallet>> {
///     let app = ctx.data_unchecked::<kota_server::App>();
///     let KotaAuthContext { sub } = ctx.data()?;
///     ...
/// }
/// ```
///
/// Use:
/// ```rust,ignore
/// async fn wallet(&self, ctx: &Context<'_>) -> async_graphql::Result<Option<Wallet>> {
///     let (app, sub) = app_and_sub_from_ctx!(ctx);
///     ...
/// }
/// ```
#[macro_export]
macro_rules! app_and_sub_from_ctx {
    ($ctx:expr) => {{
        let app = $ctx.data_unchecked::<$crate::App>();
        let sub = $ctx.data::<$crate::primitives::KotaAuthContext>()?.sub;
        (app, sub)
    }};
}
