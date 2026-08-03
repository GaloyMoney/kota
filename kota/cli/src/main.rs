#[tokio::main]
async fn main() -> anyhow::Result<()> {
    kota_cli::run().await
}
