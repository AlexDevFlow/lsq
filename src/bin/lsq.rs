#[tokio::main]
async fn main() {
    if let Err(e) = lsq::cli::run().await {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}
