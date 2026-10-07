# Build a native package

This procedure builds for the machine running it. A package built on Linux does
not run on Windows. Compilation and offline tests do not establish live
Boosteroid compatibility.

Install Python 3.11 or later, Rustup, and a native C/C++ build toolchain. On Windows,
install Visual Studio Build Tools with the Desktop development with C++ workload
and the Windows SDK. The repository pins Rust 1.99.0.

From the repository root, run:

```text
python tools/build_package.py --output dist/boosteroid.opennow-plugin
```

The command runs the Python tests, Rust formatting checks, workspace tests, and
Clippy. It verifies dependency notice hashes and the compiler's exact release
commit, then builds and packages both release executables. It refuses to replace
an existing package. Missing or unverified license texts stop the build rather
than produce an incomplete notice file.

On Windows, use `py -3 tools/build_package.py --output dist/boosteroid.opennow-plugin`
to select native Windows Python rather than MSYS2 Python. On other systems, use
`python3` instead of `python` where Python 3 has that name.
`CARGO_TARGET_DIR` can select a build cache outside the source directory.

For focused checks without packaging:

```text
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
python -m unittest discover -s tools -p "test_*.py"
```

When replacing source from a tar archive in an existing build tree, discard the
archive's old modification times with `tar -mxzf`. Otherwise Cargo can reuse an
older compiled dependency. Clean the affected package in the consumer's actual
target directory before rebuilding if that happened.

Use a compatible OpenNOW build identified in [compatibility.md](compatibility.md)
for installation. To verify installation against its actual core executable, run:

```text
python tools/verify_host.py --core /path/to/opennow-core --package dist/boosteroid.opennow-plugin
```

On Windows, use `py -3` and the path to `opennow-core.exe`. This check uses a
temporary data directory. It verifies consent, installation, native control
startup, signed-out account state, disablement, and uninstall without accessing
your existing OpenNOW profile. It does not start login or allocate a game.

Never treat these checks as evidence that Boosteroid accepted authentication,
started a game, or terminated a remote seat.
