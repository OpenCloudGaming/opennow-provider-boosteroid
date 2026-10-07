use boosteroid_control::{Provider, dispatcher};
use std::path::PathBuf;
mod native_environment;

fn main() {
    native_environment::prepare_before_threads();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => std::process::exit(1),
    };
    let result = runtime.block_on(async {
        let root = std::env::var_os("OPENNOW_PLUGIN_DATA_DIR")
            .map(PathBuf::from)
            .ok_or(())?;
        let provider = Provider::open(&root).map_err(|_| ())?;
        dispatcher::run(
            provider,
            tokio::io::BufReader::new(tokio::io::stdin()),
            tokio::io::stdout(),
        )
        .await
        .map_err(|_| ())
    });
    runtime.shutdown_timeout(std::time::Duration::from_secs(2));
    if result.is_err() {
        std::process::exit(1);
    }
}
