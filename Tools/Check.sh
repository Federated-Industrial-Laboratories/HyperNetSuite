#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Check the independent client; failures return a nonzero status.
set -euo pipefail
cd -- "$(dirname -- "$0")/.."
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
