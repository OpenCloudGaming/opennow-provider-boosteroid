#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p evidence
cargo fmt --check
cargo test --offline --locked 2>&1 | tee evidence/tests.log
cargo clippy --offline --locked --all-targets -- -D warnings 2>&1 | tee evidence/clippy.log
if [[ "${1:-}" == windows ]]; then
  cargo clippy --offline --locked --target x86_64-pc-windows-gnu --all-targets -- -D warnings 2>&1 | tee evidence/windows-check.log
fi
