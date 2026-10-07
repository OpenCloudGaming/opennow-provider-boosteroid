# Vendored h264-reader 0.9.0 (modified)

This directory is `h264-reader` 0.9.0 as published on crates.io, with the changes listed below.
The original `LICENSE-APACHE`, `LICENSE-MIT`, README, CHANGELOG, `Cargo.toml.orig` and all other
files are unchanged. The crate is licensed `MIT/Apache-2.0`; `LICENSE-MIT` states
"Copyright (c) 2018 David Holroyd". Upstream: <https://github.com/dholroyd/h264-reader>.

## Provenance

| Item | Value |
| --- | --- |
| Crate | `h264-reader` 0.9.0 |
| Source | `registry+https://github.com/rust-lang/crates.io-index` |
| crates.io checksum (sha256 of the `.crate`, as in `Cargo.lock`) | `131aec76030da5ef1abb6cc2690e6a003d99ab1a4a75abb1c30974c76d900e79` |
| VCS commit (`.cargo_vcs_info.json`) | `6059084cc49a08abf1ee537629089a9fd7ab4b8a` |

## Why

`hex-slice` 0.1.4, a normal dependency of upstream 0.9.0, publishes no license or copyright text.
Upstream uses it only to format bytes in two `Debug` implementations. The vendored copy formats
them with a small local type and keeps the SPS/PPS/slice parsers, bit reader and everything else
unmodified.

## Changes

1. `Cargo.toml`: `[dependencies.hex-slice]` is now `[dev-dependencies.hex-slice]`. Tests and
   `examples/dump.rs` still use it, but a dependent workspace does not resolve dev-dependencies, so
   `hex-slice` is not in the dependency graph. `Cargo.toml.orig` is left as published.
2. `src/nal/mod.rs`: removed `use hex_slice::AsHex;`. Added `pub(crate) struct PlainHex` with a
   `LowerHex` impl that joins bytes with a space when asked and forwards the caller's format spec to each byte.
   - `impl Debug for RefNalReader`: `plain_hex(true)` became `PlainHex(.., true)`.
3. `src/nal/sei/mod.rs`: `use hex_slice::AsHex;` became `use crate::nal::PlainHex;`.
   - `impl Debug for SeiMessage`: `plain_hex(false)` became `PlainHex(.., false)`.
4. `src/nal/mod.rs` (end of file): test module `plain_hex_equivalence` checks that `PlainHex` output equals
   `hex-slice` output for `{:02x}` and `{:x}`, with and without separators, for lengths 0, 1, 2, 3, 17 and 256.

To audit, diff this directory against the unpacked crates.io 0.9.0 crate: exactly `Cargo.toml`,
`src/nal/mod.rs` and `src/nal/sei/mod.rs` differ, and this file is added.
