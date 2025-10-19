mod app;
mod commands;
mod dummy_cli;

#[tokio::main]
async fn main() {
    if let Err(err) = app::run().await {
        eprintln!("{err}");
        std::process::exit(1);
    }
}
