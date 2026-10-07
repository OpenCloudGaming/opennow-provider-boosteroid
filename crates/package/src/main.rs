use std::path::Path;

fn main() {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    if arguments.len() != 4 {
        eprintln!(
            "Usage: boosteroid-package <control executable> <media executable> <third-party notices> <output.opennow-plugin>"
        );
        std::process::exit(2);
    }
    if boosteroid_package::create(
        Path::new(&arguments[0]),
        Path::new(&arguments[1]),
        Path::new(&arguments[2]),
        Path::new(&arguments[3]),
    )
    .is_err()
    {
        eprintln!(
            "Could not create the package; verify the native build artifacts and output directory"
        );
        std::process::exit(1);
    }
}
