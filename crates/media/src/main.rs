#[tokio::main]
async fn main() {
    if std::env::args_os().len() != 1 {
        eprintln!("Media worker accepts only the private host bootstrap");
        std::process::exit(1);
    }
    let code = if boosteroid_media::worker::run().await.is_ok() {
        0
    } else {
        eprintln!("Native media worker stopped after a transport or authorization failure");
        1
    };
    std::process::exit(code);
}
